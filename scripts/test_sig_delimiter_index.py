#!/usr/bin/env python3
"""Check signature evidence scope and delimiter work using tiny source fixtures.

The actual embedded evidence batch is executed; no repository corpus or Rust build is run.
"""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest

GUARD = Path(__file__).with_name('check_sig_case_coverage.sh')


def batch_program():
    text = GUARD.read_text()
    start = text.index("<<'PYEOF'\n", text.index('run_evidence_validations() {')) + len("<<'PYEOF'\n")
    end = text.index('sig = tomllib.loads(', start)
    program = text[start:end]
    assert program.count('code = "".join(out)') == 1
    assert program.count('        namespace = {}') == 1
    return program.replace('code = "".join(out)', 'code = MeasuredText("".join(out))').replace(
        '        namespace = {}', '        namespace = {"MeasuredText": MeasuredText}'
    )


class MeasuredText(str):
    characters = 0

    def __getitem__(self, key):
        result = super().__getitem__(key)
        return type(self)(result) if isinstance(key, slice) else result

    def __iter__(self):
        type(self).characters += len(self)
        return super().__iter__()


def run_batch(files, requests):
    with tempfile.TemporaryDirectory(prefix='gateway-sig-depth-') as directory:
        root = Path(directory)
        for name, source in files.items():
            (root / name).write_text(source)
        arguments = [str(root)]
        for name, kind, evidence, call in requests:
            arguments.append('\x1f'.join((str(root / name), kind, evidence, call, 'fixture evidence rejected')))
        old_arguments = sys.argv
        namespace = {'MeasuredText': MeasuredText}
        output = io.StringIO()
        MeasuredText.characters = 0
        try:
            sys.argv = ['signature-fixture', *arguments]
            with contextlib.redirect_stderr(output):
                exec(compile(batch_program(), '<signature-batch>', 'exec'), namespace)
            error = None
        except SystemExit as failure:
            error = failure.code
        finally:
            sys.argv = old_arguments
        return error, output.getvalue(), namespace, MeasuredText.characters


class SignatureDelimiterTests(unittest.TestCase):
    def test_many_evidence_queries_do_not_repeat_prefix_scans(self):
        source = ''.join(f'#[test]\nfn case_{index}() {{\n assert!(true);\n}}\n' for index in range(40))
        requests = [('a.rs', 'runtime', f'fn case_{index}', 'assert!') for index in range(40)]
        result = run_batch({'a.rs': source}, requests + list(reversed(requests)))
        self.assertIsNone(result[0], result[1])
        self.assertLessEqual(result[3], len(source), 'delimiter work must read the file once, not a prefix per query')
        self.assertGreater(result[3], 0, 'the work observer must see actual delimiter indexing')

    def test_every_offset_matches_independent_prefix_counts(self):
        source = 'fn main() {\n let x = ([{1}]);\n assert!(true);\n}\n'
        result = run_batch({'a.rs': source}, [('a.rs', 'compile', 'assert!', '')])
        self.assertIsNone(result[0], result[1])
        validator = result[2]['namespace']
        code = str(validator['code'])
        for end in [*range(len(code) + 1), *reversed(range(len(code) + 1))]:
            prefix = code[:end]
            expected = {opening: prefix.count(opening) - prefix.count(closing)
                        for opening, closing in zip('{([', '})]')}
            self.assertEqual(validator['delimiter_depth'](end), expected, f'offset {end}')

    def test_file_cache_does_not_mix_scope_or_rebuild_on_return(self):
        files = {
            'a.rs': 'fn main() {\n assert!(true);\n}\n',
            'b.rs': 'fn helper() {}\nfn main() {\n assert!(true);\n}\n',
        }
        requests = [(name, 'compile', 'assert!', '') for name in ['a.rs', 'b.rs', 'a.rs', 'b.rs']]
        result = run_batch(files, requests)
        self.assertIsNone(result[0], result[1])
        self.assertLessEqual(result[3], sum(map(len, files.values())), 'cached file views must retain their depth index')

    def test_cached_files_retain_their_own_evidence_names(self):
        files = {
            'a.rs': '#[test]\nfn first() {\n assert!(true);\n}\n',
            'b.rs': 'mod unrelated {}\n#[test]\nfn second() {\n assert!(true);\n}\n',
        }
        requests = [(name, 'runtime', 'fn ' + function, 'assert!')
                    for name, function in [('a.rs', 'first'), ('b.rs', 'second'), ('a.rs', 'first'), ('b.rs', 'second')]]
        result = run_batch(files, requests)
        self.assertIsNone(result[0], result[1])

    def test_equal_offsets_in_different_files_keep_independent_depth(self):
        tail = 'fn main() {\n assert!(true);\n}\n'
        files = {'a.rs': '       \n' + tail, 'b.rs': 'mod x {\n' + tail + '}\n'}
        result = run_batch(files, [('a.rs', 'compile', 'assert!', ''), ('b.rs', 'compile', 'assert!', '')])
        self.assertEqual(result[0], 1)
        self.assertIn('b.rs: no executable fn main', result[1])

    def test_missing_source_remains_an_error(self):
        with self.assertRaises(FileNotFoundError):
            run_batch({}, [('absent.rs', 'compile', 'assert!', '')])

    def test_comment_string_and_character_delimiters_are_not_scope(self):
        source = '''/* nested /* {[( */ )]} */
const TEXT: &str = r###"{[("###;
const CHAR: char = '}';
fn main() {
 let text = "}])";
 assert!(true);
}
'''
        result = run_batch({'a.rs': source}, [('a.rs', 'compile', 'assert!', '')])
        self.assertIsNone(result[0], result[1])

    def test_nested_runtime_and_direct_harness_remain_valid(self):
        fixtures = [
            ('nested_runtime', 'fn check_me', 'assert!',
             '#[cfg(test)]\nmod tests {\n #[test]\n fn check_me() { assert!(true); }\n}\n'),
            ('harness', 'check_me', 'cases.compile_fail("fixture.rs")',
             '#[test]\nfn check_me() {\n cases.compile_fail("fixture.rs");\n}\n'),
        ]
        for kind, evidence, call, source in fixtures:
            with self.subTest(kind=kind):
                result = run_batch({'a.rs': source}, [('a.rs', kind, evidence, call)])
                self.assertIsNone(result[0], result[1])

    def test_negative_depths_and_indirect_harness_are_rejected(self):
        for delimiter in '})]':
            with self.subTest(delimiter=delimiter):
                source = delimiter + '\nfn main() { assert!(true); }\n'
                result = run_batch({'a.rs': source}, [('a.rs', 'compile', 'assert!', '')])
                self.assertEqual(result[0], 1)
                self.assertIn('no executable fn main', result[1])
        for prefix, suffix in [('{ ', ' }'), ('consume(', ')')]:
            source = '#[test]\nfn check_me() {\n' + prefix + 'cases.compile_fail("fixture.rs");' + suffix + '\n}\n'
            result = run_batch({'a.rs': source}, [('a.rs', 'harness', 'check_me', 'cases.compile_fail("fixture.rs")')])
            self.assertEqual(result[0], 1)
            self.assertIn('compile-fail call is not active', result[1])

    def test_inactive_or_missing_evidence_is_rejected(self):
        fixtures = [
            ('line comment', '// fn main() { assert!(true); }\n', 'no executable fn main'),
            ('block comment', '/* fn main() { assert!(true); } */\n', 'no executable fn main'),
            ('string main', 'const S: &str = "fn main() { assert!(true); }";\n', 'no executable fn main'),
            ('raw string main', 'const S: &str = r#"fn main() { assert!(true); }"#;\n', 'no executable fn main'),
            ('nested main', 'mod nested {\n fn main() { assert!(true); }\n}\n', 'no executable fn main'),
            ('disabled main', '#[cfg(any())]\nfn main() { assert!(true); }\n', 'no executable fn main'),
            ('missing call', 'fn main() {\n let x = 1;\n}\n', 'evidence is not active'),
            ('comment call', 'fn main() {\n // assert!(true);\n}\n', 'evidence is not active'),
            ('string call', 'fn main() {\n let x = "assert!(true)";\n}\n', 'evidence is not active'),
            ('nested brace call', 'fn main() {\n { assert!(true); }\n}\n', 'evidence is not active'),
            ('nested paren call', 'fn main() {\n consume(assert!(true));\n}\n', 'evidence is not active'),
            ('nested bracket call', 'fn main() {\n let x = [assert!(true)];\n}\n', 'evidence is not active'),
            ('attributed call', 'fn main() {\n #[cfg(any())]\n assert!(true);\n}\n', 'evidence is not active'),
            ('unclosed comment', '/* fn main() {}\n', 'unterminated block comment'),
            ('unclosed function', 'fn main() {\n assert!(true);\n', 'function body is unterminated'),
        ]
        for name, source, diagnostic in fixtures:
            with self.subTest(name=name):
                result = run_batch({'a.rs': source}, [('a.rs', 'compile', 'assert!', '')])
                self.assertEqual(result[0], 1)
                self.assertIn(diagnostic, result[1])


if __name__ == '__main__':
    unittest.main()
