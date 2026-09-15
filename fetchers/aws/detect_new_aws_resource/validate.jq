# These checks validate configuration, not actual event delivery or pattern coverage.
def status($ok): if $ok then "PASS" else "FAIL" end;
.results.eventbridge.rules[$rule_name] as $entry
| ($entry.schedule // "") as $schedule
| ($entry.rule.EventPattern // "") as $raw_pattern
| (try ($raw_pattern | fromjson) catch null) as $pattern
| (($pattern | type) == "object" and ($pattern | length) > 0) as $has_pattern
| ($schedule != "") as $has_schedule
| (.results.sns.topics[$topic_name].topic.TopicArn // "") as $topic_arn
| .results.validation_results.rule_checks[$rule_name] = {
    present: status($entry != null),
    enabled: status($entry.rule.State == "ENABLED" or $entry.rule.State == "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"),
    event_pattern: (if $raw_pattern == "" and $has_schedule then "NOT_APPLICABLE" else status($has_pattern) end),
    sns_target: status($topic_arn != "" and any($entry.targets[]?; .Arn == $topic_arn)),
    trigger_type: (if $has_pattern and $has_schedule then "event_and_schedule"
                   elif $has_pattern then "event"
                   elif $has_schedule then "schedule"
                   else "unconfigured" end)
  }
| .results.validation_results.interval_checks[$rule_name] = {
    status: (if $has_schedule then
               status($schedule | test("^rate\\((1 minute|[2-5] minutes)\\)$"))
             elif $has_pattern then "NOT_APPLICABLE"
             else "FAIL" end),
    schedule: $schedule,
    reason: (if $has_schedule then "Scheduled rules must use rate(1 minute) through rate(5 minutes)."
             elif $has_pattern then "Event-driven rule; no monitoring schedule is required."
             else "No valid event pattern or schedule found." end)
  }
