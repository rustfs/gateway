#!/usr/bin/env bash
set -euo pipefail

# WHAT THIS CHECKS
#   The four issue templates, their configuration, and the pull-request template retain the
#   machine-readable structure that later live issue and PR gates depend on.

ROOT="${GATEWAY_CHECK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

command -v ruby >/dev/null 2>&1 || fail 'required command is missing: ruby'

# -E and the magic comment pin UTF-8 for the script and every file it reads, whatever the host locale.
ruby -E UTF-8 -ryaml - "$ROOT" <<'RUBY'
# encoding: utf-8
root = ARGV.fetch(0)
template_dir = File.join(root, ".github", "ISSUE_TEMPLATE")
paths = {
  "config" => File.join(template_dir, "config.yml"),
  "task" => File.join(template_dir, "task.md"),
  "bug" => File.join(template_dir, "bug.md"),
  "protocol" => File.join(template_dir, "protocol-mismatch.md"),
  "operation" => File.join(template_dir, "new-operation.md"),
  "pr" => File.join(root, ".github", "pull_request_template.md"),
  "agents" => File.join(root, "AGENTS.md")
}
paths.each do |name, path|
  abort("ERROR: #{name} contract input is missing: #{path.delete_prefix(root + '/')}") unless File.file?(path)
end

def require_equal(actual, expected, message)
  abort("ERROR: #{message}") unless actual == expected
end

def front_matter(path)
  lines = File.readlines(path)
  abort("ERROR: #{File.basename(path)} has no opening front matter") unless lines.first&.strip == "---"
  relative_end = lines.drop(1).index { |line| line.strip == "---" }
  abort("ERROR: #{File.basename(path)} has no closing front matter") unless relative_end
  ending = relative_end + 1
  metadata = YAML.safe_load(lines[1...ending].join)
  abort("ERROR: #{File.basename(path)} front matter must be a mapping") unless metadata.is_a?(Hash)
  [metadata, lines[(ending + 1)..-1].join]
rescue Psych::SyntaxError => error
  abort("ERROR: #{File.basename(path)} front matter is invalid YAML: #{error.message}")
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

def markdown_sections(body)
  lines = body.lines
  headings = []
  comment_state = {open: false}
  fence = nil
  lines.each_with_index do |line, index|
    visible = visible_line(line, comment_state)
    if fence
      token = visible.match(/^ {0,3}([`~]{3,})/)&.[](1)
      fence = nil if token && token[0] == fence[0] && token.length >= fence.length
      next
    end
    token = visible.match(/^ {0,3}([`~]{3,})/)&.[](1)
    if token
      fence = token
      next
    end
    match = visible.match(/^## ([^\r\n]+?)\s*$/)
    headings << [match[1], index] if match
  end
  abort("ERROR: markdown contains an unterminated HTML comment") if comment_state[:open]
  abort("ERROR: markdown contains an unterminated fenced block") if fence

  headings.each_with_index.map do |(name, index), position|
    ending = position + 1 < headings.length ? headings[position + 1][1] : lines.length
    [name, lines[(index + 1)...ending].join]
  end
end

def section_map(body, expected, label)
  sections = markdown_sections(body)
  require_equal(sections.map(&:first), expected, "#{label} headings changed, moved, or gained a decoy")
  sections.to_h
end

def without_comments(text)
  text.gsub(/<!--.*?-->/m, "")
end

def require_once(text, needle, message)
  require_equal(text.scan(Regexp.new(Regexp.escape(needle))).length, 1, message)
end

def require_count(text, needle, expected, message)
  require_equal(text.scan(Regexp.new(Regexp.escape(needle))).length, expected, message)
end

def checklist_block(section, label)
  lines = without_comments(section).lines.map(&:rstrip)
  first = lines.index { |line| line.start_with?("- [ ] ") }
  abort("ERROR: #{label} has no checklist items") unless first
  block = lines[first..-1].join("\n").strip
  abort("ERROR: #{label} contains content after its checklist") unless block.lines.all? { |line| line.start_with?("- [ ] ") || line.start_with?("      ") }
  block
end

agents = File.read(paths.fetch("agents"))
pr_body = File.read(paths.fetch("pr"))
pr_sections = section_map(
  pr_body,
  ["Summary", "Verification", "Role Verdicts", "Breaking Change", "Checklist"],
  "pull request template"
)
agents_sections = markdown_sections(agents).to_h
require_equal(
  checklist_block(pr_sections.fetch("Checklist"), "pull request template"),
  checklist_block(agents_sections.fetch("PR Checklist"), "AGENTS.md"),
  "pull request checklist drifted from AGENTS.md"
)

config = YAML.safe_load(File.read(paths.fetch("config")))
abort("ERROR: config.yml must be a mapping") unless config.is_a?(Hash)
require_equal(config.keys, ["blank_issues_enabled", "contact_links"], "issue template config keys changed")
require_equal(config.fetch("blank_issues_enabled"), false, "blank issues must remain disabled")
require_equal(config.fetch("contact_links"), [{
                "name" => "Security vulnerability",
                "url" => "https://github.com/rustfs/gateway/security/advisories/new",
                "about" => "Report security issues privately. Do NOT open a public issue."
              }], "contact links must name only enabled destinations")

issue_contracts = {
  "task" => {
    "name" => "Implementation Task",
    "about" => "Self-contained implementation task (any device / any agent can pick it up)",
    "title" => "[gateway][P?-??] ",
    "labels" => "task"
  },
  "bug" => {
    "name" => "Bug report",
    "about" => "A defect in the gateway framework itself",
    "title" => "[bug] ",
    "labels" => "bug"
  },
  "protocol" => {
    "name" => "Protocol mismatch",
    "about" => "gateway behaves differently from real AWS S3 on the wire",
    "title" => "[protocol] <Operation>: <one-line difference>",
    "labels" => "protocol-mismatch"
  },
  "operation" => {
    "name" => "New S3 operation",
    "about" => "Request support for an S3 operation that is not implemented yet",
    "title" => "[op] <OperationName>",
    "labels" => "new-operation"
  }
}
bodies = {}
issue_contracts.each do |name, expected|
  metadata, body = front_matter(paths.fetch(name))
  require_equal(metadata, expected, "#{name} template front matter changed")
  bodies[name] = body
end

task_headings = [
  "0. Metadata",
  "1. Background and goal (self-contained)",
  "2. Required reading",
  "3. Files touched",
  "4. Design (decided — do not redesign)",
  "5. Key code skeleton (signature level)",
  "6. Protocol evidence",
  "7. Full case list (exhaustive, negatives included)",
  "8. Acceptance criteria (machine-decidable)",
  "9. Verification commands (copy-pasteable, with expected output)",
  "10. Out of scope (scope fence)",
  "11. Definition of Done",
  "12. Starting work on a new machine"
]
task_sections = section_map(bodies.fetch("task"), task_headings, "task template")
task_visible = without_comments(bodies.fetch("task"))
require_once(task_visible, "> Epic: rustfs/backlog#1677", "task template must name Parent #1677 once")
%w[generated/** model/s3.json Cargo.lock].each do |forbidden|
  require_once(without_comments(task_sections.fetch("2. Required reading")), forbidden, "task forbidden-input list changed: #{forbidden}")
end
require_once(
  without_comments(task_sections.fetch("7. Full case list (exhaustive, negatives included)")),
  "the number of negative cases MUST be >= the number of positive cases",
  "task template lost the negative-case requirement"
)
handoff = task_sections.fetch("12. Starting work on a new machine")
%w[-\ Done: -\ Not\ done: -\ Next\ command: -\ Gotcha:].each do |escaped|
  field = escaped.gsub("\\", "")
  require_once(without_comments(handoff), field, "task Handoff field changed: #{field}")
end

bug_sections = section_map(
  bodies.fetch("bug"),
  ["Minimal reproduction (mandatory)", "Expected vs actual", "Panic?", "Versions", "Anything else"],
  "bug template"
)
bug_visible = without_comments(bodies.fetch("bug"))
require_once(bug_visible, "SECURITY.md", "bug template lost the private security route")
require_once(bug_visible, "RUST_BACKTRACE=1", "bug template lost the panic evidence command")
require_count(bug_sections.fetch("Versions"), "rustc -vV", 2, "bug template lost the compiler version field")

protocol_sections = section_map(
  bodies.fetch("protocol"),
  [
    "1. Operation and request shape",
    "2. Expected vs actual",
    "3. Wire evidence (MANDATORY — provide at least one, both is better)",
    "4. Reference implementation used for comparison",
    "5. AWS documentation",
    "6. Environment"
  ],
  "protocol mismatch template"
)
protocol_visible = without_comments(bodies.fetch("protocol"))
require_once(protocol_visible, "will be closed immediately", "protocol template lost the no-evidence close rule")
wire = protocol_sections.fetch("3. Wire evidence (MANDATORY — provide at least one, both is better)")
{"REDACTION" => 1, "aws --debug" => 2, "tcpdump" => 1, "mitmproxy" => 1}.each do |token, count|
  require_count(wire, token, count, "protocol wire requirement changed: #{token}")
end

operation_sections = section_map(
  bodies.fetch("operation"),
  ["Operation", "Use case (one sentence)", "Client dependency", "Operation family", "Notes"],
  "new operation template"
)
operation_intro = bodies.fetch("operation").split(/^## Operation\s*$/, 2).first
%w[ops/<snake_name>.rs impl\ Operation //!\ Shares:].each do |escaped|
  token = escaped.gsub("\\", "")
  require_once(operation_intro, token, "new operation single-file contract changed: #{token}")
end
require_once(operation_sections.fetch("Operation"), "AWS API documentation URL", "new operation template lost the official URL field")

require_once(pr_sections.fetch("Summary"), "Closes #", "pull request template lost its issue-closing field")
%w[
  cargo\ fmt\ --all\ --check
  cargo\ clippy\ --workspace\ --all-targets\ --\ -D\ warnings
  cargo\ test\ --workspace
  cargo\ xtask\ verify\ --crate
].each do |escaped|
  command = escaped.gsub("\\", "")
  require_once(pr_sections.fetch("Verification"), command, "pull request verification command changed: #{command}")
end
role_visible = without_comments(pr_sections.fetch("Role Verdicts"))
require_once(role_visible, "- simplicity-adversary:", "pull request template lost the role verdict row")
breaking_visible = without_comments(pr_sections.fetch("Breaking Change"))
require_once(breaking_visible, "- [ ] BREAKING", "pull request template lost the BREAKING checkbox")
require_once(pr_sections.fetch("Breaking Change"), "migration path", "pull request template lost the migration prompt")
RUBY

printf 'OK: issue and pull-request template structure matches the repository contract\n'
