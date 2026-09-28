#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   The ADR directory keeps one continuous numbered record whose file names, metadata, five-part
#   structure and hand-maintained index agree. It checks shape, not the truth of a decision.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ADR_DIR="$ROOT/docs/adr"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

command -v ruby >/dev/null 2>&1 || fail 'required command is missing: ruby'
command -v git >/dev/null 2>&1 || fail 'required command is missing: git'
[[ -d "$ADR_DIR" ]] || fail 'docs/adr is missing'

BASE=""
if [[ -n "${GATEWAY_ADR_BASE:-}" ]]; then
    BASE="$(git -C "$ROOT" rev-parse --verify "${GATEWAY_ADR_BASE}^{commit}")" || \
        fail 'cannot resolve GATEWAY_ADR_BASE'
    HEAD_COMMIT="$(git -C "$ROOT" rev-parse --verify HEAD^{commit})" || fail 'cannot resolve HEAD'
    [[ "$BASE" != "$HEAD_COMMIT" ]] || fail 'GATEWAY_ADR_BASE must not resolve to HEAD'
else
    PR_MERGE_BASE=""
    if [[ "${GITHUB_ACTIONS:-}" == "true" && "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
        read -r -a head_line <<<"$(git -C "$ROOT" rev-list --parents -n 1 HEAD)"
        if [[ "${#head_line[@]}" -eq 3 ]]; then
            PR_MERGE_BASE="${head_line[1]}"
        fi
    fi
    if [[ -n "$PR_MERGE_BASE" ]]; then
        BASE="$PR_MERGE_BASE"
    elif git -C "$ROOT" rev-parse --verify origin/main^{commit} >/dev/null 2>&1; then
        BASE="$(git -C "$ROOT" merge-base HEAD origin/main)" || fail 'cannot resolve the ADR merge base'
        HEAD_COMMIT="$(git -C "$ROOT" rev-parse --verify HEAD^{commit})" || fail 'cannot resolve HEAD'
        if [[ "$BASE" == "$HEAD_COMMIT" ]]; then
            # A checkout exactly at origin/main is the normal pre-commit state. Its parent is the
            # last independent before-state; using HEAD itself would let committed ADR drift bless
            # its own contents. A root commit has no trustworthy predecessor and must fail closed.
            BASE="$(git -C "$ROOT" rev-parse --verify HEAD^ 2>/dev/null)" || \
                fail 'implicit ADR base at origin/main has no prior commit'
        fi
    elif ! git -C "$ROOT" diff --quiet HEAD -- docs/adr; then
        # A fresh test sandbox has no remote, but its dirty ADR worktree still
        # makes HEAD a real before-state. A clean committed tree has no such
        # evidence and must not compare itself with itself.
        BASE="$(git -C "$ROOT" rev-parse --verify HEAD^{commit})" || fail 'cannot resolve the current ADR base'
    else
        fail 'cannot resolve a trusted ADR base; CI must pass GATEWAY_ADR_BASE'
    fi
fi
git -C "$ROOT" cat-file -e "${BASE}^{commit}" 2>/dev/null || fail "ADR base is not a commit: ${BASE}"

# -E and the magic comment pin UTF-8 for the script and every file it reads, whatever the host locale.
ruby -E UTF-8 - "$ADR_DIR" "$ROOT" "$BASE" <<'RUBY'
# encoding: utf-8
require "date"
require "open3"

directory = ARGV.fetch(0)
root = ARGV.fetch(1)
base = ARGV.fetch(2)
# rustfs/backlog#1720 records this one pre-guard historical spelling. Renaming an accepted ADR is
# a protected deletion/addition, so the closeout freezes exactly this exception instead of quietly
# rewriting history. No second `ADR-NNNN-*` path is accepted.
LEGACY_NAME = "ADR-0007-ext-field-codec.md"

def require_equal(actual, expected, message)
  abort("ERROR: #{message}") unless actual == expected
end

def without_comments(text)
  text.gsub(/<!--.*?-->/m, "")
end

def visible_line(line, comment_state)
  visible = +""
  remaining = line
  loop do
    if comment_state[:open]
      ending = remaining.index("-->")
      return visible unless ending
      remaining = remaining[(ending + 3)..-1]
      comment_state[:open] = false
    else
      opening = remaining.index("<!--")
      unless opening
        visible << remaining
        return visible
      end
      visible << remaining[0...opening]
      remaining = remaining[(opening + 4)..-1]
      comment_state[:open] = true
    end
  end
end

def visible_markdown_entries(body, label)
  lines = []
  comment_state = {open: false}
  fence = nil
  body.lines.each_with_index do |line, index|
    if fence
      closing = line.match(/\A {0,3}(#{Regexp.escape(fence[0])}{#{fence.length},})[ \t]*(?:\r?\n)?\z/)
      fence = nil if closing
      next
    end

    visible = visible_line(line, comment_state)
    opening = visible.match(/\A {0,3}(`{3,}|~{3,})(.*?)(?:\r?\n)?\z/)
    if opening
      token = opening[1]
      info = opening[2]
      # A fence marker is one pure run. An immediately adjacent other marker
      # (` ```~ `) is not reinterpreted as an info string, and backtick fence
      # info may not itself contain a backtick (CommonMark §4.5).
      mixed = info.start_with?("`", "~")
      invalid_backtick_info = token[0] == "`" && info.include?("`")
      fence = token unless mixed || invalid_backtick_info
      next if fence
    end
    if opening && (mixed || invalid_backtick_info)
      lines << [visible, index]
      next
    end
    lines << [visible, index]
  end
  abort("ERROR: #{label} has an unterminated HTML comment") if comment_state[:open]
  abort("ERROR: #{label} has an unterminated fenced block") if fence
  lines
end

def visible_markdown_lines(body, label)
  visible_markdown_entries(body, label).map(&:first)
end

def markdown_sections(body, label)
  sections = []
  current = nil
  visible_markdown_lines(body, label).each do |line|
    match = line.match(/^## ([^\r\n]+?)\s*$/)
    if match
      sections << current if current
      current = [match[1], +""]
    elsif current
      current[1] << line
    end
  end
  sections << current if current
  sections
end

def meaningful?(section)
  without_comments(section).lines.any? do |line|
    text = line.strip
    !text.empty? && !text.match?(/^\|?[-:| ]+\|?$/)
  end
end

readme_path = File.join(directory, "README.md")
template_path = File.join(directory, "0000-template.md")
abort("ERROR: docs/adr/README.md is missing") unless File.file?(readme_path)
abort("ERROR: docs/adr/0000-template.md is missing") unless File.file?(template_path)
abort("ERROR: docs/adr/README.md must not be a symlink") if File.symlink?(readme_path)
abort("ERROR: docs/adr/0000-template.md must not be a symlink") if File.symlink?(template_path)

entries = Dir.children(directory).sort
unexpected = entries.reject do |name|
  name == "README.md" || name == "0000-template.md" || name == LEGACY_NAME ||
    name.match?(/\A[0-9]{4}-[a-z0-9]+(?:-[a-z0-9]+)*\.md\z/)
end
abort("ERROR: invalid ADR path(s): #{unexpected.join(', ')}") unless unexpected.empty?

adr_names = entries.select do |name|
  name == LEGACY_NAME || (name != "0000-template.md" && name.match?(/\A[0-9]{4}-[a-z0-9]+(?:-[a-z0-9]+)*\.md\z/))
end
abort("ERROR: no accepted ADR records found") if adr_names.empty?
number_for_name = lambda do |name|
  name == LEGACY_NAME ? 7 : Integer(name[0, 4], 10)
end

def git_text(root, *arguments)
  output, error, status = Open3.capture3("git", "-C", root, *arguments)
  abort("ERROR: git #{arguments.join(' ')} failed: #{error.strip}") unless status.success?
  output
end

baseline_paths = git_text(root, "ls-tree", "-r", "--name-only", base, "--", "docs/adr").lines.map(&:strip)
baseline_by_number = {}
baseline_paths.each do |relative|
  name = File.basename(relative)
  next unless name == LEGACY_NAME || (name != "0000-template.md" && name.match?(/\A[0-9]{4}-[a-z0-9]+(?:-[a-z0-9]+)*\.md\z/))
  number = format("%04d", number_for_name.call(name))
  source = git_text(root, "show", "#{base}:#{relative}")
  baseline_by_number[number] = {"name" => name, "source" => source}
end

def lifecycle_metadata(source, label)
  entries = visible_markdown_entries(source, label)
  first_section = entries.index { |line, _| line.start_with?("## ") } || entries.length
  prefix = entries[0...first_section]
  status = prefix.select { |line, _| line.start_with?("- Status: ") }
  relation = prefix.select { |line, _| line.start_with?("- Supersedes / Superseded by: ") }
  abort("ERROR: #{label} lifecycle metadata is malformed") unless status.length == 1 && relation.length == 1
  values = [
    status.first[0].sub("- Status: ", "").strip,
    relation.first[0].sub("- Supersedes / Superseded by: ", "").strip,
  ]
  [values, [status.first[1], relation.first[1]]]
end

def immutable_adr_body(source, label)
  _, lifecycle_offsets = lifecycle_metadata(source, label)
  source.lines.each_with_index.reject { |_, index| lifecycle_offsets.include?(index) }.map(&:first).join
end

numbers = adr_names.map { |name| number_for_name.call(name) }
require_equal(numbers.uniq.length, numbers.length, "ADR numbers must be unique")
require_equal(numbers.sort, (1..numbers.max).to_a, "ADR numbers must be continuous from 0001")

expected_sections = ["Context", "Decision", "Evidence", "Rejected alternatives", "Consequences"]
records = {}
relations = {}
adr_names.each do |name|
  path = File.join(directory, name)
  abort("ERROR: docs/adr/#{name} must be a regular file") unless File.file?(path)
  abort("ERROR: docs/adr/#{name} must not be a symlink") if File.symlink?(path)
  source = File.read(path)
  first = source.lines.find { |line| !line.strip.empty? }&.strip
  match = first&.match(/\A# ADR-([0-9]{4}): (.+)\z/)
  abort("ERROR: #{name} must start with '# ADR-NNNN: Title'") unless match
  number = format("%04d", number_for_name.call(name))
  require_equal(match[1], number, "#{name} H1 number does not match its file name")
  title = match[2]
  abort("ERROR: #{name} has a placeholder or empty title") if title.empty? || title.include?("<Title>")

  visible_source = visible_markdown_lines(source, name)
  first_section = visible_source.index { |line| line.start_with?("## ") } || visible_source.length
  metadata_pairs = visible_source[0...first_section].map do |line|
    item = line.match(/^- ([^:]+): (.+)$/)
    [item[1], item[2].strip] if item
  end.compact
  require_equal(metadata_pairs.length, 4, "#{name} must declare exactly four metadata rows")
  metadata = metadata_pairs.to_h
  require_equal(metadata.keys, ["Status", "Date", "Trigger", "Supersedes / Superseded by"],
                "#{name} metadata keys or order changed")
  status = metadata.fetch("Status")
  unless status == "Accepted" || status == "Rejected" || status.match?(/\ASuperseded by ADR-[0-9]{4}\z/)
    abort("ERROR: #{name} has invalid status: #{status}")
  end
  date = metadata.fetch("Date")
  begin
    Date.iso8601(date)
  rescue Date::Error
    abort("ERROR: #{name} has an invalid date")
  end
  abort("ERROR: #{name} has an invalid date") unless date.match?(/\A[0-9]{4}-[0-9]{2}-[0-9]{2}\z/)
  trigger = metadata.fetch("Trigger")
  abort("ERROR: #{name} has no concrete trigger") if trigger.empty? || trigger.include?("<")
  relation = metadata.fetch("Supersedes / Superseded by")
  unless relation == "none" || relation.match?(/\AADR-[0-9]{4}(?:\s*\/\s*ADR-[0-9]{4})*\z/)
    abort("ERROR: #{name} has invalid supersession metadata: #{relation}")
  end

  sections = markdown_sections(source, name)
  require_equal(sections.map(&:first), expected_sections, "#{name} must retain the five ADR sections in order")
  section_map = sections.to_h
  abort("ERROR: #{name} has an empty Evidence section") unless meaningful?(section_map.fetch("Evidence"))
  abort("ERROR: #{name} has an empty Rejected alternatives section") unless meaningful?(section_map.fetch("Rejected alternatives"))

  records[number] = {"title" => title, "status" => status}
  relations[number] = relation.scan(/ADR-([0-9]{4})/).flatten

  baseline = baseline_by_number[number]
  next unless baseline
  require_equal(name, baseline.fetch("name"), "ADR-#{number} merged filename is immutable")
  require_equal(
    immutable_adr_body(source, name),
    immutable_adr_body(baseline.fetch("source"), baseline.fetch("name")),
    "ADR-#{number} merged body changed outside lifecycle metadata"
  )
end

relations.each do |number, targets|
  targets.each do |target|
    abort("ERROR: ADR-#{number} references missing ADR-#{target}") unless records.key?(target)
    abort("ERROR: ADR-#{number} cannot supersede itself") if target == number
    unless relations.fetch(target).include?(number)
      abort("ERROR: ADR-#{number} and ADR-#{target} supersession metadata is not bidirectional")
    end
    number_status_target = records.fetch(number).fetch("status")[/Superseded by ADR-([0-9]{4})/, 1]
    target_status_target = records.fetch(target).fetch("status")[/Superseded by ADR-([0-9]{4})/, 1]
    unless number_status_target == target || target_status_target == number
      abort("ERROR: ADR-#{number} and ADR-#{target} relation has no superseded side")
    end
  end
  status_target = records.fetch(number).fetch("status")[/Superseded by ADR-([0-9]{4})/, 1]
  next unless status_target
  abort("ERROR: ADR-#{number} status is missing its supersession metadata") unless targets.include?(status_target)
end

baseline_by_number.each do |number, baseline|
  abort("ERROR: merged ADR-#{number} disappeared") unless records.key?(number)
  (old_status, old_relation), = lifecycle_metadata(baseline.fetch("source"), baseline.fetch("name"))
  new_status = records.fetch(number).fetch("status")
  new_relation = relations.fetch(number)
  next if new_status == old_status && new_relation == old_relation.scan(/ADR-([0-9]{4})/).flatten

  target = new_status[/\ASuperseded by ADR-([0-9]{4})\z/, 1]
  unless old_status == "Accepted" && old_relation == "none" && target &&
         new_relation == [target] && !baseline_by_number.key?(target) && relations.fetch(target).include?(number)
    abort("ERROR: ADR-#{number} lifecycle metadata changed without a paired new superseding ADR")
  end
end

template = File.read(template_path)
visible_template = visible_markdown_lines(template, "0000-template.md")
template_section = visible_template.index { |line| line.start_with?("## ") } || visible_template.length
template_intro = visible_template[0...template_section]
require_equal(template_intro.first&.strip, "# ADR-NNNN: <Title>", "ADR template H1 changed")
template_metadata = template_intro.map do |line|
  item = line.match(/^- ([^:]+): (.+)$/)
  [item[1], item[2].strip] if item
end.compact
require_equal(template_metadata, [
                ["Status", "Accepted"],
                ["Date", "YYYY-MM-DD"],
                ["Trigger", "<axiom | crate boundary | licensing/dependency policy>"],
                ["Supersedes / Superseded by", "<none | ADR-NNNN>"]
              ], "ADR template metadata changed")
template_sections = markdown_sections(template, "0000-template.md")
require_equal(template_sections.map(&:first), expected_sections, "ADR template sections changed or gained a decoy")
%w[Evidence Rejected\ alternatives].each do |escaped|
  section = escaped.gsub("\\", "")
  abort("ERROR: ADR template #{section} guidance is empty") unless meaningful?(template_sections.to_h.fetch(section))
end

readme = File.read(readme_path)
readme_sections = markdown_sections(readme, "README.md").to_h
required_readme_sections = ["When you MUST write an ADR", "Rules", "Structure", "Index"]
require_equal(readme_sections.keys, required_readme_sections, "ADR README sections changed or gained a decoy")
triggers = without_comments(readme_sections.fetch("When you MUST write an ADR")).lines.grep(/^\d+\. /)
require_equal(triggers.length, 3, "ADR README must retain exactly three numbered triggers")
trigger_text = triggers.join(" ")
%w[axioms crate\ boundary licensing\ or\ dependency\ policy].each do |escaped|
  phrase = escaped.gsub("\\", "")
  abort("ERROR: ADR README trigger changed: #{phrase}") unless trigger_text.include?(phrase)
end
abort("ERROR: ADR README lost the non-trigger exclusion") unless readme_sections.fetch("When you MUST write an ADR").include?("do NOT write an ADR")

rules = readme_sections.fetch("Rules")
[
  "NNNN-kebab-case-title.md",
  "Accepted",
  "Superseded by ADR-NNNN",
  "Rejected",
  "There is no `Proposed` state",
  "Merged ADRs are immutable",
  "Every ADR MUST carry an `## Evidence` section",
  "Every ADR MUST carry a `## Rejected alternatives` section"
].each do |rule|
  abort("ERROR: ADR README rule changed: #{rule}") unless rules.include?(rule)
end

index_pairs = without_comments(readme_sections.fetch("Index")).lines.map do |line|
  match = line.match(/^\| ([0-9]{4}) \| (.+) \| (.+) \|\s*$/)
  [match[1], {"title" => match[2], "status" => match[3]}] if match
end.compact
require_equal(index_pairs.map(&:first).uniq.length, index_pairs.length, "ADR README index contains a duplicate number")
index_rows = index_pairs.to_h
require_equal(index_rows, records, "ADR README index does not match the numbered records")
RUBY

printf 'OK: ADR file names, structure, metadata and index form one continuous record\n'
