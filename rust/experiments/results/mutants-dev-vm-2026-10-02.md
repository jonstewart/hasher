# Mutation testing: first deep-testing run and triage

- date: 2026-10-02 (run) / 2026-10-03 (triage and this report)
- host: dev-vm, Linux 6.18.52 x86_64, 4 cores, Intel(R) Xeon(R) CPU E5645 @ 2.40GHz, 11 GiB RAM (6 GiB free, 5 GiB swap, idle at report time)
- toolchain: rustc 1.98.1 (48a229cea 2026-09-01); cargo-mutants 27.1.0; cargo-nextest 0.9.136; cargo-fuzz 0.13.1; Kani Rust Verifier 0.68.0 (CBMC 6.11.0)
- commit: 91b82b5 (branch `hashset-lookup-perf`), the last commit before this report's own commit

This is Task 18 of `docs/superpowers/plans/2026-10-02-rust-deep-testing.md` (Step 4, the
mutation-testing run and its triage, through Step 6, the final gate and commit). The first
run itself is reported here from the merged outcome files and run logs under
`.superpowers/sdd/2026-10-02-rust-deep-testing/mutants/`; triage of its survivors was done as
two prior tasks (18b-1, 18b-2) whose per-row results are reproduced in full below. The cited
`.superpowers/...` run logs and reports are local to this VM and not tracked in git; the
tables in this document are self-contained and do not depend on them.

## 1. First run: per-crate totals

| crate | tested | caught | missed | timeout | unviable |
|---|---:|---:|---:|---:|---:|
| hset | 1905 | 1408 | 332 | 32 | 133 |
| hset-cli | 136 | 41 | 16 | 0 | 79 |

Recount (outcome files, one mutant per line):

```
$ wc -l mutants/hset-{caught,missed,timeout,unviable}.txt
  1408 mutants/hset-caught.txt
   332 mutants/hset-missed.txt
    32 mutants/hset-timeout.txt
   133 mutants/hset-unviable.txt
  1905 total
$ wc -l mutants/hset-cli-{caught,missed,timeout,unviable}.txt
    41 mutants/hset-cli-caught.txt
    16 mutants/hset-cli-missed.txt
     0 mutants/hset-cli-timeout.txt
    79 mutants/hset-cli-unviable.txt
   136 total
```

Both totals match `cargo mutants --list -p hset`/`-p hset-cli` at the pre-triage
`.cargo/mutants.toml` (1905 and 136 respectively, from the run logs' `Found N mutants to
test` lines). hset's 332 missed and 32 timeout split into two triage inputs:
`group-lookup-missed.txt` (216, `hset/src/lookup/*.rs`) + `group-rest-missed.txt` (116,
everything else in hset) = 332 missed; the 32 timeout lines of `hset-timeout.txt` split 29
lookup / 3 non-lookup by file.

## 2. Post-triage outcome

The 332 hset survivors and 16 hset-cli survivors were triaged in two prior tasks: 18b-1
(`mutants/triage-lookup.md`, the 216 `lookup/*.rs` survivors plus their 29 timeout lines) and
18b-2 (`mutants/triage-rest.md`, the remaining 116 hset survivors, the 16 hset-cli survivors,
and the 3 non-lookup timeout lines). Both tables record one outcome per survivor; none were
left open.

| | killed by a new test | excluded with reason | removed (dead code) | left open | timeout (detected, no action) |
|---|---:|---:|---:|---:|---:|
| hset, lookup group | 117 | 99 | 0 | 0 | 29 |
| hset, rest of crate | 89 | 25 | 2 | 0 | 3 |
| **hset total** | **206** | **124** | **2** | **0** | **32** |
| hset-cli | 16 | 0 | 0 | 0 | 0 |

Recount (triage table outcome column, header and `|---|` separator rows excluded):

```
$ grep -c '| killed |' mutants/triage-lookup.md      # 117
$ grep -c '| excluded |' mutants/triage-lookup.md    # 99
$ grep -n 'timeout (detected)' mutants/triage-lookup.md | grep -v '^.*:Outcomes' | wc -l   # 29
$ grep -c '| killed |' mutants/triage-rest.md        # 105  (= 89 hset + 16 hset-cli)
$ grep -c '| excluded |' mutants/triage-rest.md      # 25
$ grep -c '| removed' mutants/triage-rest.md         # 2
$ grep -n 'timeout (detected)' mutants/triage-rest.md | grep -v '^.*:Outcomes' | wc -l     # 3
```

117+99+29 = 245 = the 216 lookup survivors + 29 lookup timeouts (triage-lookup.md's header:
"excluded 99, killed 117, timeout (detected) 29"). 105+25+2+3 = 135 = the 116 rest survivors +
16 hset-cli survivors + 3 non-lookup timeouts (triage-rest.md's header: "hset killed 89,
excluded 25, removed 2; hset-cli killed 16; timeout (detected) 3"). Total resolved rows
245+135 = 380 = 332 (hset missed) + 16 (hset-cli missed) + 32 (timeout), with 0 left open.

The 2 removed mutants are `ops.rs:88:46` (`+` -> `-` and `+` -> `*` in `relayout`): a dead
`None`-arm of a match that `apply()`'s type-set construction made unreachable (every target
field has a source field of its type, so the zero-fill arm could never run). The arm was
deleted from the source in commit 2b9efec ("refactor(rust): remove unused zero-fill arm in
relayout") rather than tested or excluded, and `cargo mutants -p hset --list` confirms the two
mutants no longer appear.

No bug was found while triaging these 332 + 16 survivors: `triage-rest.md`'s header records
"Bugs found: none" directly, and the lookup group's zero-bugs outcome is recorded in the
Task 18b-1 report (`task-18b1-report.md`: "117 killed, 99 excluded, 0 removed, 0 open, 0
bugs") rather than in `triage-lookup.md`'s own header, which gives outcome counts only.

## 3. Full survivor table

One row per hset/hset-cli survivor and detected timeout (380 rows), merged from
`mutants/triage-lookup.md` and `mutants/triage-rest.md` in that order. `lookup/` is prepended
to the lookup group's bare `mod.rs`/`hull.rs`/`model.rs`/`search.rs` paths to disambiguate them
from the rest group's files of the same crate; `hset-cli/main.rs` paths are already
disambiguated by their crate prefix. The "confirming run" column of the source tables is
omitted here (it is in the two triage files); outcome and test/exclude-pattern are kept.

| file:line:col | mutation | outcome | test / exclude pattern |
|---|---|---|---|
| lookup/mod.rs:147:54 | `*` → `+` | killed | `lookup::tests::bits_policy_picks_the_largest_table_within_budget` |
| lookup/mod.rs:29:9 | body → `true` | killed | `lookup::tests::is_empty_is_false_for_a_stored_hash` |
| lookup/mod.rs:147:54 | `*` → `/` | killed | `lookup::tests::bits_policy_picks_the_largest_table_within_budget` |
| lookup/mod.rs:147:31 | `*` → `+` | killed | `lookup::tests::bits_policy_picks_the_largest_table_within_budget` |
| lookup/mod.rs:149:20 | `<` → `<=` | killed | `lookup::tests::bits_policy_picks_the_largest_table_within_budget` |
| lookup/mod.rs:149:59 | `*` → `+` | killed | `lookup::tests::bits_policy_picks_the_largest_table_within_budget` |
| lookup/mod.rs:149:87 | `+` → `-` | killed | `lookup::tests::bits_policy_picks_the_largest_table_within_budget` |
| lookup/mod.rs:149:87 | `+` → `*` | killed | `lookup::tests::bits_policy_picks_the_largest_table_within_budget` |
| lookup/mod.rs:205:24 | `/` → `%` | killed | `lookup::tests::hash_count_limit_counts_whole_hashes` |
| lookup/mod.rs:205:24 | `/` → `*` | killed | `lookup::tests::hash_count_limit_counts_whole_hashes` |
| lookup/mod.rs:263:17 | `>` → `>=` | killed | `lookup::tests::hint_bits_up_to_the_maximum_are_accepted` |
| lookup/mod.rs:295:18 | `>` → `==` | killed | `lookup::tests::hash_count_limit_counts_whole_hashes` |
| lookup/mod.rs:295:18 | `>` → `>=` | killed | `lookup::tests::hash_count_limit_counts_whole_hashes` |
| lookup/mod.rs:328:17 | `match guard table.len() == BLOCK_ENTRY_LEN << bits` → `true` | killed | `lookup::tests::hint_from_parts_checks_kind_and_table_length` |
| lookup/mod.rs:328:17 | `match guard table.len() == BLOCK_ENTRY_LEN << bits` → `false` | killed | `lookup::tests::hint_from_parts_checks_kind_and_table_length` |
| lookup/mod.rs:329:17 | `match guard table.len() == HULL_ENTRY_LEN << bits` → `true` | killed | `lookup::tests::hint_from_parts_checks_kind_and_table_length` |
| lookup/mod.rs:329:17 | `match guard table.len() == HULL_ENTRY_LEN << bits` → `false` | killed | `lookup::tests::hint_from_parts_checks_kind_and_table_length` |
| lookup/mod.rs:327:15 | `>>` → `<<` | killed | `lookup::tests::hint_from_parts_checks_kind_and_table_length` |
| lookup/mod.rs:328:29 | `==` → `!=` | killed | `lookup::tests::hint_from_parts_checks_kind_and_table_length` |
| lookup/mod.rs:328:48 | `<<` → `>>` | killed | `lookup::tests::hint_from_parts_checks_kind_and_table_length` |
| lookup/mod.rs:329:29 | `==` → `!=` | killed | `lookup::tests::hint_from_parts_checks_kind_and_table_length` |
| lookup/mod.rs:329:47 | `<<` → `>>` | killed | `lookup::tests::hint_from_parts_checks_kind_and_table_length` |
| lookup/hull.rs:76:9 | body → `0` | killed | `lookup::hull::tests::width_counts_candidates` |
| lookup/hull.rs:76:9 | body → `1` | killed | `lookup::hull::tests::width_counts_candidates` |
| lookup/hull.rs:79:58 | `+` → `*` | killed | `lookup::hull::tests::width_counts_candidates` |
| lookup/hull.rs:103:11 | `<<` → `>>` | killed | `lookup::hull::tests::frac_is_the_32_bits_below_the_block_prefix` |
| lookup/hull.rs:114:5 | body → `0` | killed | `lookup::hull::tests::half_hulls_keep_only_their_turns` |
| lookup/hull.rs:126:37 | `-` → `/` | killed | `lookup::hull::tests::half_hulls_keep_only_their_turns` |
| lookup/hull.rs:150:18 | `<` → `==` | killed | `lookup::hull::tests::slope_of_fewer_than_two_points_is_zero` |
| lookup/hull.rs:150:18 | `<` → `<=` | killed | `lookup::hull::tests::slope_of_fewer_than_two_points_is_zero` |
| lookup/hull.rs:159:40 | `-` → `+` | killed | `lookup::hull::tests::slope_is_the_best_hull_edge` |
| lookup/hull.rs:159:40 | `-` → `/` | killed | `lookup::hull::tests::slope_is_the_best_hull_edge` |
| lookup/hull.rs:160:19 | `>` → `==` | killed | `lookup::hull::tests::slope_is_the_best_hull_edge` |
| lookup/hull.rs:160:19 | `>` → `<` | killed | `lookup::hull::tests::slope_is_the_best_hull_edge` |
| lookup/hull.rs:160:19 | `>` → `>=` | excluded | `hull\.rs:(160:19\|167:15): replace > with >= in choose_slope\b` |
| lookup/hull.rs:161:73 | `/` → `%` | killed | `lookup::hull::tests::slope_is_the_best_hull_edge` |
| lookup/hull.rs:161:73 | `/` → `*` | killed | `lookup::hull::tests::slope_is_the_best_hull_edge` |
| lookup/hull.rs:161:52 | `-` → `+` | killed | `lookup::hull::tests::slope_is_the_best_hull_edge` |
| lookup/hull.rs:161:52 | `-` → `/` | killed | `lookup::hull::tests::slope_is_the_best_hull_edge` |
| lookup/hull.rs:167:15 | `>` → `==` | killed | `lookup::hull::tests::chord_wins_when_the_best_edges_are_too_steep` |
| lookup/hull.rs:167:15 | `>` → `<` | killed | `lookup::hull::tests::chord_wins_when_the_best_edges_are_too_steep` |
| lookup/hull.rs:167:15 | `>` → `>=` | excluded | `hull\.rs:(160:19\|167:15): replace > with >= in choose_slope\b` |
| lookup/hull.rs:169:54 | `/` → `%` | killed | `lookup::hull::tests::chord_wins_when_the_best_edges_are_too_steep` |
| lookup/hull.rs:169:54 | `/` → `*` | killed | `lookup::hull::tests::chord_wins_when_the_best_edges_are_too_steep` |
| lookup/hull.rs:169:32 | `-` → `+` | killed | `lookup::hull::tests::chord_wins_when_the_best_edges_are_too_steep` |
| lookup/hull.rs:169:32 | `-` → `/` | killed | `lookup::hull::tests::chord_wins_when_the_best_edges_are_too_steep` |
| lookup/hull.rs:169:75 | `-` → `+` | killed | `lookup::hull::tests::chord_wins_when_the_best_edges_are_too_steep` |
| lookup/hull.rs:169:75 | `-` → `/` | killed | `lookup::hull::tests::chord_wins_when_the_best_edges_are_too_steep` |
| lookup/hull.rs:183:14 | `<` → `<=` | killed | `lookup::hull::tests::slope_ties_go_to_the_first_candidate` |
| lookup/model.rs:73:9 | body → `0` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:73:9 | body → `1` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:73:9 | body → `-1` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:73:44 | `>>` → `<<` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:73:27 | `*` → `+` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:73:27 | `*` → `/` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:78:9 | body → `0` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:78:9 | body → `1` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:78:45 | `>>` → `<<` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:78:28 | `*` → `+` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:78:28 | `*` → `/` | killed | `lookup::model::tests::full_model_scales_the_key_to_the_set` |
| lookup/model.rs:126:9 | body → `0` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:126:9 | body → `1` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:126:9 | body → `-1` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:132:58 | `/` → `%` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:132:58 | `/` → `*` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:132:38 | `+` → `-` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:132:38 | `+` → `*` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:138:9 | body → `0` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:138:9 | body → `1` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:138:45 | `>>` → `<<` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:138:28 | `*` → `+` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:138:28 | `*` → `/` | killed | `lookup::model::tests::flat_model_centres_on_the_mid_deviation` |
| lookup/model.rs:231:9 | body → `0` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:231:9 | body → `1` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:231:9 | body → `-1` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:232:44 | `+` → `-` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:232:44 | `+` → `*` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:232:86 | `/` → `%` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:232:86 | `/` → `*` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:232:65 | `+` → `-` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:232:65 | `+` → `*` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:237:9 | body → `0` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:237:9 | body → `1` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:239:28 | `*` → `+` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/model.rs:239:58 | `-` → `+` | killed | `lookup::model::tests::hull_model_centres_on_the_line_plus_mid_residual` |
| lookup/search.rs:55:9 | body → `Ok(Default::default())` | killed | `lookup::search::tests::debug_shows_the_strategy` |
| lookup/search.rs:110:9 | body → `0` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:110:9 | body → `1` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:114:23 | `/` → `%` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:114:23 | `/` → `*` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:118:38 | `*` → `/` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:126:43 | `*` → `+` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:126:36 | `-` → `/` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:133:9 | body → `0` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:133:9 | body → `1` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:133:34 | `+` → `-` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:133:34 | `+` → `*` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:133:30 | `/` → `%` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:133:30 | `/` → `*` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:134:49 | `/` → `%` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:134:49 | `/` → `*` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:134:45 | `/` → `%` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:134:45 | `/` → `*` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:139:9 | body → `0` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:139:9 | body → `1` | killed | `lookup::search::tests::region_radius_is_the_clamped_residual_quantile` |
| lookup/search.rs:145:9 | body → `(0, 1)` | killed | `lookup::search::tests::recursive_search_stays_inside_a_corrupt_window` |
| lookup/search.rs:145:9 | body → `(1, 1)` | killed | `lookup::search::tests::recursive_search_stays_inside_a_corrupt_window` |
| lookup/search.rs:145:51 | `-` → `+` | excluded | `search\.rs:(145:51: replace - with [+/]\|147:24: replace \+ with [-*]) in Strategy<.*>::region\b` |
| lookup/search.rs:145:51 | `-` → `/` | excluded | `search\.rs:(145:51: replace - with [+/]\|147:24: replace \+ with [-*]) in Strategy<.*>::region\b` |
| lookup/search.rs:147:24 | `+` → `-` | excluded | `search\.rs:(145:51: replace - with [+/]\|147:24: replace \+ with [-*]) in Strategy<.*>::region\b` |
| lookup/search.rs:147:24 | `+` → `*` | excluded | `search\.rs:(145:51: replace - with [+/]\|147:24: replace \+ with [-*]) in Strategy<.*>::region\b` |
| lookup/search.rs:147:20 | `+` → `*` | killed | `lookup::search::tests::recursive_search_survives_a_huge_region_radius` |
| lookup/search.rs:165:30 | `<=` → `>` | excluded | `search\.rs:165:(30: replace <= with >\|26: replace \* with [+/]\|20: replace - with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:165:26 | `*` → `+` | excluded | `search\.rs:165:(30: replace <= with >\|26: replace \* with [+/]\|20: replace - with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:165:26 | `*` → `/` | excluded | `search\.rs:165:(30: replace <= with >\|26: replace \* with [+/]\|20: replace - with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:165:20 | `-` → `+` | excluded | `search\.rs:165:(30: replace <= with >\|26: replace \* with [+/]\|20: replace - with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:183:46 | `-` → `+` | excluded | `search\.rs:(183:46: replace - with [+/]\|183:35: replace - with \+\|184:41: replace \* with \+\|196:39: replace \+ with [-*]\|196:35: replace - with [+/]\|197:41: replace \* with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:183:46 | `-` → `/` | excluded | `search\.rs:(183:46: replace - with [+/]\|183:35: replace - with \+\|184:41: replace \* with \+\|196:39: replace \+ with [-*]\|196:35: replace - with [+/]\|197:41: replace \* with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:183:35 | `-` → `+` | excluded | `search\.rs:(183:46: replace - with [+/]\|183:35: replace - with \+\|184:41: replace \* with \+\|196:39: replace \+ with [-*]\|196:35: replace - with [+/]\|197:41: replace \* with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:184:41 | `*` → `+` | excluded | `search\.rs:(183:46: replace - with [+/]\|183:35: replace - with \+\|184:41: replace \* with \+\|196:39: replace \+ with [-*]\|196:35: replace - with [+/]\|197:41: replace \* with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:188:61 | `+` → `*` | excluded | `search\.rs:(188:61\|200:57): replace \+ with \* in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:195:49 | `-` → `/` | killed | `lookup::search::tests::recursive_search_steps_past_a_run_of_zero_keys` |
| lookup/search.rs:196:39 | `+` → `-` | excluded | `search\.rs:(183:46: replace - with [+/]\|183:35: replace - with \+\|184:41: replace \* with \+\|196:39: replace \+ with [-*]\|196:35: replace - with [+/]\|197:41: replace \* with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:196:39 | `+` → `*` | excluded | `search\.rs:(183:46: replace - with [+/]\|183:35: replace - with \+\|184:41: replace \* with \+\|196:39: replace \+ with [-*]\|196:35: replace - with [+/]\|197:41: replace \* with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:196:35 | `-` → `+` | excluded | `search\.rs:(183:46: replace - with [+/]\|183:35: replace - with \+\|184:41: replace \* with \+\|196:39: replace \+ with [-*]\|196:35: replace - with [+/]\|197:41: replace \* with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:196:35 | `-` → `/` | excluded | `search\.rs:(183:46: replace - with [+/]\|183:35: replace - with \+\|184:41: replace \* with \+\|196:39: replace \+ with [-*]\|196:35: replace - with [+/]\|197:41: replace \* with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:197:41 | `*` → `+` | excluded | `search\.rs:(183:46: replace - with [+/]\|183:35: replace - with \+\|184:41: replace \* with \+\|196:39: replace \+ with [-*]\|196:35: replace - with [+/]\|197:41: replace \* with \+) in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:200:57 | `+` → `*` | excluded | `search\.rs:(188:61\|200:57): replace \+ with \* in Strategy<.*>::find_recursive\b` |
| lookup/search.rs:214:9 | body → `true` | killed | `lookup::search::tests::staged_batch_needs_small_windows` |
| lookup/search.rs:214:9 | body → `false` | killed | `lookup::search::tests::staged_batch_needs_small_windows` |
| lookup/search.rs:225:9 | body → `Default::default()` | excluded | `Strategy<.*>::ptr_at\b` |
| lookup/search.rs:225:21 | `*` → `+` | excluded | `Strategy<.*>::ptr_at\b` |
| lookup/search.rs:225:21 | `*` → `/` | excluded | `Strategy<.*>::ptr_at\b` |
| lookup/search.rs:231:9 | body → `()` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:231:46 | `&` → `\|` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:231:46 | `&` → `^` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:231:61 | `-` → `+` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:231:61 | `-` → `/` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:232:44 | `+` → `-` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:232:56 | `*` → `+` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:232:56 | `*` → `/` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:232:50 | `-` → `+` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:234:17 | `<` → `==` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:234:17 | `<` → `>` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:234:17 | `<` → `<=` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:236:15 | `+=` → `*=` | excluded | `Strategy<.*>::prefetch_window\b` |
| lookup/search.rs:244:9 | body → `()` | excluded | `replace Strategy<.*>::prefetch_for with \(\)` |
| lookup/search.rs:245:20 | `<=` → `>` | excluded | `search\.rs:(245:20: replace <= with >\|245:16: replace \* with [+/]\|247:35: replace == with !=\|253:49: replace \* with [+/]) in Strategy<.*>::prefetch_for\b` |
| lookup/search.rs:245:16 | `*` → `+` | excluded | `search\.rs:(245:20: replace <= with >\|245:16: replace \* with [+/]\|247:35: replace == with !=\|253:49: replace \* with [+/]) in Strategy<.*>::prefetch_for\b` |
| lookup/search.rs:245:16 | `*` → `/` | excluded | `search\.rs:(245:20: replace <= with >\|245:16: replace \* with [+/]\|247:35: replace == with !=\|253:49: replace \* with [+/]) in Strategy<.*>::prefetch_for\b` |
| lookup/search.rs:247:35 | `==` → `!=` | excluded | `search\.rs:(245:20: replace <= with >\|245:16: replace \* with [+/]\|247:35: replace == with !=\|253:49: replace \* with [+/]) in Strategy<.*>::prefetch_for\b` |
| lookup/search.rs:253:49 | `*` → `+` | excluded | `search\.rs:(245:20: replace <= with >\|245:16: replace \* with [+/]\|247:35: replace == with !=\|253:49: replace \* with [+/]) in Strategy<.*>::prefetch_for\b` |
| lookup/search.rs:253:49 | `*` → `/` | excluded | `search\.rs:(245:20: replace <= with >\|245:16: replace \* with [+/]\|247:35: replace == with !=\|253:49: replace \* with [+/]) in Strategy<.*>::prefetch_for\b` |
| lookup/search.rs:264:19 | `>` → `==` | excluded | `search\.rs:264:19: replace > with (==\|>=) in Strategy<.*>::lower_bound_binary\b` |
| lookup/search.rs:264:19 | `>` → `>=` | excluded | `search\.rs:264:19: replace > with (==\|>=) in Strategy<.*>::lower_bound_binary\b` |
| lookup/search.rs:291:32 | `*` → `+` | excluded | `search\.rs:(291:32: replace \* with \+\|309:51: replace \+ with [-*]\|310:55: replace \+ with \*) in Strategy<.*>::kary_step\b` |
| lookup/search.rs:309:51 | `+` → `-` | excluded | `search\.rs:(291:32: replace \* with \+\|309:51: replace \+ with [-*]\|310:55: replace \+ with \*) in Strategy<.*>::kary_step\b` |
| lookup/search.rs:309:51 | `+` → `*` | excluded | `search\.rs:(291:32: replace \* with \+\|309:51: replace \+ with [-*]\|310:55: replace \+ with \*) in Strategy<.*>::kary_step\b` |
| lookup/search.rs:310:55 | `+` → `*` | excluded | `search\.rs:(291:32: replace \* with \+\|309:51: replace \+ with [-*]\|310:55: replace \+ with \*) in Strategy<.*>::kary_step\b` |
| lookup/search.rs:318:23 | `>` → `==` | excluded | `search\.rs:318:(23: replace > with (==\|>=)\|44: replace > with (==\|<\|>=)\|40: replace \* with [+/]\|34: replace - with \+) in Strategy<.*>::lower_bound_kary\b` |
| lookup/search.rs:318:23 | `>` → `>=` | excluded | `search\.rs:318:(23: replace > with (==\|>=)\|44: replace > with (==\|<\|>=)\|40: replace \* with [+/]\|34: replace - with \+) in Strategy<.*>::lower_bound_kary\b` |
| lookup/search.rs:318:18 | `-` → `+` | killed | `tests/prop_lookup.rs::kary_stops_at_eight_hashes_anywhere_in_the_array` |
| lookup/search.rs:318:44 | `>` → `==` | excluded | `search\.rs:318:(23: replace > with (==\|>=)\|44: replace > with (==\|<\|>=)\|40: replace \* with [+/]\|34: replace - with \+) in Strategy<.*>::lower_bound_kary\b` |
| lookup/search.rs:318:44 | `>` → `<` | excluded | `search\.rs:318:(23: replace > with (==\|>=)\|44: replace > with (==\|<\|>=)\|40: replace \* with [+/]\|34: replace - with \+) in Strategy<.*>::lower_bound_kary\b` |
| lookup/search.rs:318:44 | `>` → `>=` | excluded | `search\.rs:318:(23: replace > with (==\|>=)\|44: replace > with (==\|<\|>=)\|40: replace \* with [+/]\|34: replace - with \+) in Strategy<.*>::lower_bound_kary\b` |
| lookup/search.rs:318:40 | `*` → `+` | excluded | `search\.rs:318:(23: replace > with (==\|>=)\|44: replace > with (==\|<\|>=)\|40: replace \* with [+/]\|34: replace - with \+) in Strategy<.*>::lower_bound_kary\b` |
| lookup/search.rs:318:40 | `*` → `/` | excluded | `search\.rs:318:(23: replace > with (==\|>=)\|44: replace > with (==\|<\|>=)\|40: replace \* with [+/]\|34: replace - with \+) in Strategy<.*>::lower_bound_kary\b` |
| lookup/search.rs:318:34 | `-` → `+` | excluded | `search\.rs:318:(23: replace > with (==\|>=)\|44: replace > with (==\|<\|>=)\|40: replace \* with [+/]\|34: replace - with \+) in Strategy<.*>::lower_bound_kary\b` |
| lookup/search.rs:368:36 | `<=` → `>` | excluded | `search\.rs:(368:(36: replace <= with >\|32: replace \* with [+/]\|26: replace - with \+)\|370:35: replace == with !=) in Strategy<.*>::find_in_prefetched\b` |
| lookup/search.rs:368:32 | `*` → `+` | excluded | `search\.rs:(368:(36: replace <= with >\|32: replace \* with [+/]\|26: replace - with \+)\|370:35: replace == with !=) in Strategy<.*>::find_in_prefetched\b` |
| lookup/search.rs:368:32 | `*` → `/` | excluded | `search\.rs:(368:(36: replace <= with >\|32: replace \* with [+/]\|26: replace - with \+)\|370:35: replace == with !=) in Strategy<.*>::find_in_prefetched\b` |
| lookup/search.rs:368:26 | `-` → `+` | excluded | `search\.rs:(368:(36: replace <= with >\|32: replace \* with [+/]\|26: replace - with \+)\|370:35: replace == with !=) in Strategy<.*>::find_in_prefetched\b` |
| lookup/search.rs:370:35 | `==` → `!=` | excluded | `search\.rs:(368:(36: replace <= with >\|32: replace \* with [+/]\|26: replace - with \+)\|370:35: replace == with !=) in Strategy<.*>::find_in_prefetched\b` |
| lookup/search.rs:388:27 | `+` → `*` | excluded | `search\.rs:(388:27: replace \+ with \*\|402:23: replace < with (==\|>\|<=)\|407:40: replace < with <=) in Strategy<.*>::batch_staged\b` |
| lookup/search.rs:402:23 | `<` → `==` | excluded | `search\.rs:(388:27: replace \+ with \*\|402:23: replace < with (==\|>\|<=)\|407:40: replace < with <=) in Strategy<.*>::batch_staged\b` |
| lookup/search.rs:402:23 | `<` → `>` | excluded | `search\.rs:(388:27: replace \+ with \*\|402:23: replace < with (==\|>\|<=)\|407:40: replace < with <=) in Strategy<.*>::batch_staged\b` |
| lookup/search.rs:402:23 | `<` → `<=` | excluded | `search\.rs:(388:27: replace \+ with \*\|402:23: replace < with (==\|>\|<=)\|407:40: replace < with <=) in Strategy<.*>::batch_staged\b` |
| lookup/search.rs:407:40 | `<` → `<=` | excluded | `search\.rs:(388:27: replace \+ with \*\|402:23: replace < with (==\|>\|<=)\|407:40: replace < with <=) in Strategy<.*>::batch_staged\b` |
| lookup/search.rs:459:26 | `<` → `==` | excluded | `search\.rs:(459:26: replace < with (==\|>\|<=)\|460:56: replace \* with /) in Strategy<.*>::batch_passes\b` |
| lookup/search.rs:459:26 | `<` → `>` | excluded | `search\.rs:(459:26: replace < with (==\|>\|<=)\|460:56: replace \* with /) in Strategy<.*>::batch_passes\b` |
| lookup/search.rs:459:26 | `<` → `<=` | excluded | `search\.rs:(459:26: replace < with (==\|>\|<=)\|460:56: replace \* with /) in Strategy<.*>::batch_passes\b` |
| lookup/search.rs:460:56 | `*` → `/` | excluded | `search\.rs:(459:26: replace < with (==\|>\|<=)\|460:56: replace \* with /) in Strategy<.*>::batch_passes\b` |
| lookup/search.rs:460:64 | `+` → `*` | killed | `tests/prop_lookup.rs::passes_prefetch_regions_from_each_query_hash` |
| lookup/search.rs:498:43 | `==` → `!=` | excluded | `search\.rs:(498:43: replace == with !=\|520:46: replace && with \\|\\|\|520:63: replace > with (==\|<\|>=)\|520:59: replace \* with [+/]\|520:53: replace - with \+) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:520:46 | `&&` → `\|\|` | excluded | `search\.rs:(498:43: replace == with !=\|520:46: replace && with \\|\\|\|520:63: replace > with (==\|<\|>=)\|520:59: replace \* with [+/]\|520:53: replace - with \+) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:520:63 | `>` → `==` | excluded | `search\.rs:(498:43: replace == with !=\|520:46: replace && with \\|\\|\|520:63: replace > with (==\|<\|>=)\|520:59: replace \* with [+/]\|520:53: replace - with \+) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:520:63 | `>` → `<` | excluded | `search\.rs:(498:43: replace == with !=\|520:46: replace && with \\|\\|\|520:63: replace > with (==\|<\|>=)\|520:59: replace \* with [+/]\|520:53: replace - with \+) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:520:63 | `>` → `>=` | excluded | `search\.rs:(498:43: replace == with !=\|520:46: replace && with \\|\\|\|520:63: replace > with (==\|<\|>=)\|520:59: replace \* with [+/]\|520:53: replace - with \+) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:520:59 | `*` → `+` | excluded | `search\.rs:(498:43: replace == with !=\|520:46: replace && with \\|\\|\|520:63: replace > with (==\|<\|>=)\|520:59: replace \* with [+/]\|520:53: replace - with \+) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:520:59 | `*` → `/` | excluded | `search\.rs:(498:43: replace == with !=\|520:46: replace && with \\|\\|\|520:63: replace > with (==\|<\|>=)\|520:59: replace \* with [+/]\|520:53: replace - with \+) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:520:53 | `-` → `+` | excluded | `search\.rs:(498:43: replace == with !=\|520:46: replace && with \\|\\|\|520:63: replace > with (==\|<\|>=)\|520:59: replace \* with [+/]\|520:53: replace - with \+) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:523:57 | `-` → `+` | killed | `tests/prop_lookup.rs::lanes_clamp_the_first_probe_into_the_window` |
| lookup/search.rs:523:57 | `-` → `/` | killed | `tests/prop_lookup.rs::lanes_clamp_the_first_probe_into_the_window` |
| lookup/search.rs:563:38 | `>` → `<` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:566:51 | `+` → `*` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:566:47 | `+` → `*` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:571:38 | `>` → `<` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:574:64 | `+` → `*` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:586:40 | `match guard (ln.hi - ln.lo) * L > self.cfg.window_prefetch_bytes` → `true` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:586:40 | `match guard (ln.hi - ln.lo) * L > self.cfg.window_prefetch_bytes` → `false` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:586:60 | `>` → `==` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:586:60 | `>` → `<` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:586:60 | `>` → `>=` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:586:56 | `*` → `+` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:586:56 | `*` → `/` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:586:47 | `-` → `+` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:587:43 | `-=` → `/=` | excluded | `search\.rs:(5(63\|71):38: replace > with <\|566:(47\|51): replace \+ with \*\|574:64: replace \+ with \*\|586:40: replace match guard .* with (true\|false)\|586:60: replace > with (==\|<\|>=)\|586:56: replace \* with [+/]\|586:47: replace - with \+\|587:43: replace -= with /=) in Strategy<.*>::batch_lanes\b` |
| lookup/search.rs:588:54 | `-` → `+` | killed | `tests/prop_lookup.rs::lanes_clamp_re_aimed_probes_into_the_bracket` |
| lookup/search.rs:588:54 | `-` → `/` | killed | `tests/prop_lookup.rs::lanes_clamp_re_aimed_probes_into_the_bracket` |
| lookup/search.rs:636:29 | `+` → `*` | excluded | `search\.rs:(636\|742):29: replace \+ with \* in <impl Lookup for (Strategy\|DynBasic)<.*>>::equal_range\b` |
| lookup/search.rs:647:22 | `<` → `==` | excluded | `search\.rs:647:22: replace < with (==\|>\|<=) in <impl Lookup for Strategy<.*>>::contains_batch\b` |
| lookup/search.rs:647:22 | `<` → `>` | excluded | `search\.rs:647:22: replace < with (==\|>\|<=) in <impl Lookup for Strategy<.*>>::contains_batch\b` |
| lookup/search.rs:647:22 | `<` → `<=` | excluded | `search\.rs:647:22: replace < with (==\|>\|<=) in <impl Lookup for Strategy<.*>>::contains_batch\b` |
| lookup/search.rs:722:9 | body → `0` | killed | `lookup::tests::unsupported_lengths_fall_back_to_generic_search` |
| lookup/search.rs:722:9 | body → `1` | killed | `lookup::tests::unsupported_lengths_fall_back_to_generic_search` |
| lookup/search.rs:742:29 | `+` → `*` | excluded | `search\.rs:(636\|742):29: replace \+ with \* in <impl Lookup for (Strategy\|DynBasic)<.*>>::equal_range\b` |
| lookup/mod.rs:151:18 | `+=` → `*=` | timeout (detected) | — |
| lookup/hull.rs:250:17 | `<` → `==` | timeout (detected) | — |
| lookup/hull.rs:250:17 | `<` → `>` | timeout (detected) | — |
| lookup/hull.rs:250:50 | `==` → `!=` | timeout (detected) | — |
| lookup/hull.rs:251:15 | `+=` → `*=` | timeout (detected) | — |
| lookup/search.rs:231:48 | delete `!` | timeout (detected) | also excluded by `Strategy<.*>::prefetch_window\b` (whole-function prefetch exclusion) |
| lookup/search.rs:232:44 | `+` → `*` | timeout (detected) | also excluded by `Strategy<.*>::prefetch_window\b` (whole-function prefetch exclusion) |
| lookup/search.rs:236:15 | `+=` → `-=` | timeout (detected) | also excluded by `Strategy<.*>::prefetch_window\b` (whole-function prefetch exclusion) |
| lookup/search.rs:264:19 | `>` → `<` | timeout (detected) | — |
| lookup/search.rs:278:15 | `+=` → `*=` | timeout (detected) | — |
| lookup/search.rs:287:22 | `-` → `+` | timeout (detected) | — |
| lookup/search.rs:310:27 | `==` → `!=` | timeout (detected) | — |
| lookup/search.rs:342:47 | `+=` → `*=` | timeout (detected) | — |
| lookup/search.rs:514:23 | `+=` → `*=` | timeout (detected) | — |
| lookup/search.rs:550:23 | `>` → `>=` | timeout (detected) | — |
| lookup/search.rs:552:20 | delete `!` | timeout (detected) | — |
| lookup/search.rs:565:61 | `-` → `/` | timeout (detected) | — |
| lookup/search.rs:568:40 | `+` → `-` | timeout (detected) | — |
| lookup/search.rs:568:40 | `+` → `*` | timeout (detected) | — |
| lookup/search.rs:584:30 | `<` → `<=` | timeout (detected) | — |
| lookup/search.rs:600:25 | `-=` → `+=` | timeout (detected) | — |
| lookup/search.rs:600:25 | `-=` → `/=` | timeout (detected) | — |
| lookup/search.rs:640:17 | `+=` → `*=` | timeout (detected) | — |
| lookup/search.rs:704:18 | `<` → `<=` | timeout (detected) | — |
| lookup/search.rs:705:26 | `+` → `*` | timeout (detected) | — |
| lookup/search.rs:705:38 | `/` → `%` | timeout (detected) | — |
| lookup/search.rs:705:32 | `-` → `+` | timeout (detected) | — |
| lookup/search.rs:707:26 | `+` → `*` | timeout (detected) | — |
| lookup/search.rs:744:17 | `+=` → `*=` | timeout (detected) | — |
| builder.rs:117:9 | body → `vec![]` | killed | `builder::tests::builder_reports_types_line_count_and_file_size` |
| builder.rs:212:15 | `+=` → `*=` | killed | `builder::tests::builder_reports_types_line_count_and_file_size` |
| builder.rs:310:9 | body → `Ok(0)` | killed | `builder::tests::builder_reports_types_line_count_and_file_size` |
| builder.rs:310:9 | body → `Ok(1)` | killed | `builder::tests::builder_reports_types_line_count_and_file_size` |
| builder.rs:347:27 | `match guard value.len() == 8` → `true` | killed | `builder::tests::values_render_as_numbers_only_at_eight_bytes` |
| builder.rs:350:30 | `match guard value.len() == 8` → `true` | killed | `builder::tests::values_render_as_numbers_only_at_eight_bytes` |
| builder.rs:350:30 | `match guard value.len() == 8` → `false` | killed | `builder::tests::values_render_as_numbers_only_at_eight_bytes` |
| builder.rs:350:42 | `==` → `!=` | killed | `builder::tests::values_render_as_numbers_only_at_eight_bytes` |
| builder.rs:360:27 | `match guard value.len() == 8` → `true` | killed | `builder::tests::values_render_as_numbers_only_at_eight_bytes` |
| builder.rs:363:30 | `match guard value.len() == 8` → `true` | killed | `builder::tests::values_render_as_numbers_only_at_eight_bytes` |
| builder.rs:409:48 | `-` → `/` | killed | `builder::tests::timestamp_formatting_across_months_centuries_and_eras` |
| builder.rs:409:33 | `+` → `-` | killed | `builder::tests::timestamp_formatting_across_months_centuries_and_eras` |
| builder.rs:409:33 | `+` → `*` | killed | `builder::tests::timestamp_formatting_across_months_centuries_and_eras` |
| builder.rs:414:29 | `+` → `-` | killed | `builder::tests::timestamp_formatting_across_months_centuries_and_eras` |
| builder.rs:414:29 | `+` → `*` | killed | `builder::tests::timestamp_formatting_across_months_centuries_and_eras` |
| hash_type.rs:15:13 | `<<` → `>>` | excluded | `hash_type\.rs:15:13: replace << with >>` |
| hash_type.rs:143:9 | body → `false` | killed | `hash_type::tests::lengths_match_reference` |
| hashset.rs:19:9 | body → `Ok(Default::default())` | killed | `hashset::tests::accessors_expose_the_loaded_file` |
| hashset.rs:57:9 | body → `Vec::leak(Vec::new())` | killed | `hashset::tests::accessors_expose_the_loaded_file` |
| hashset.rs:57:9 | body → `Vec::leak(vec![0])` | killed | `hashset::tests::accessors_expose_the_loaded_file` |
| hashset.rs:57:9 | body → `Vec::leak(vec![1])` | killed | `hashset::tests::accessors_expose_the_loaded_file` |
| hashset.rs:73:9 | body → `0` | killed | `hashset::tests::accessors_expose_the_loaded_file` |
| hashset.rs:73:9 | body → `1` | killed | `hashset::tests::accessors_expose_the_loaded_file` |
| hashset.rs:95:9 | body → `Vec::leak(Vec::new())` | killed | `hashset::tests::accessors_expose_the_loaded_file` |
| hashset.rs:203:55 | `+=` → `-=` | killed | `hashset::tests::verify_reports_mean_window_and_duplicate_records` |
| hashset.rs:203:55 | `+=` → `*=` | killed | `hashset::tests::verify_reports_mean_window_and_duplicate_records` |
| hashset.rs:210:21 | `>` → `<` | killed | `hashset::tests::verify_reports_mean_window_and_duplicate_records` |
| hashset.rs:245:30 | `+=` → `*=` | killed | `hashset::tests::verify_reports_mean_window_and_duplicate_records` |
| hashset.rs:262:16 | delete `!` | killed | `hashset::tests::verify_reports_mean_window_and_duplicate_records` |
| hashset.rs:263:54 | `/` → `%` | killed | `hashset::tests::verify_reports_mean_window_and_duplicate_records` |
| hashset.rs:263:54 | `/` → `*` | killed | `hashset::tests::verify_reports_mean_window_and_duplicate_records` |
| hex.rs:68:53 | `\|` → `^` | excluded | `hex\.rs:(68:53: replace \\| with \^ in scalar::decode_into\|170:26: replace \\| with \^ in simd::nibbles\|18[89]:28: replace \\| with \^ in simd::decode_block)\b` |
| hex.rs:170:26 | `\|` → `^` | excluded | `hex\.rs:(68:53: replace \\| with \^ in scalar::decode_into\|170:26: replace \\| with \^ in simd::nibbles\|18[89]:28: replace \\| with \^ in simd::decode_block)\b` |
| hex.rs:183:20 | `\|` → `^` | killed | `hex::tests::simd_decode_rejects_bad_digits_in_both_halves_of_a_lane` |
| hex.rs:188:28 | `\|` → `^` | excluded | `hex\.rs:(68:53: replace \\| with \^ in scalar::decode_into\|170:26: replace \\| with \^ in simd::nibbles\|18[89]:28: replace \\| with \^ in simd::decode_block)\b` |
| hex.rs:189:28 | `\|` → `^` | excluded | `hex\.rs:(68:53: replace \\| with \^ in scalar::decode_into\|170:26: replace \\| with \^ in simd::nibbles\|18[89]:28: replace \\| with \^ in simd::decode_block)\b` |
| hex.rs:239:29 | `*` → `+` | excluded | `hex\.rs:(239:29: replace \* with [+/] in encode_to_string\|307:16: replace / with % in check_rows\|316:(22\|27): replace \* with [+/] in encode_rows\|316:35: replace \+ with \* in encode_rows)\b` |
| hex.rs:239:29 | `*` → `/` | excluded | `hex\.rs:(239:29: replace \* with [+/] in encode_to_string\|307:16: replace / with % in check_rows\|316:(22\|27): replace \* with [+/] in encode_rows\|316:35: replace \+ with \* in encode_rows)\b` |
| hex.rs:243:31 | `*` → `+` | killed | `hex::tests::encode_to_string_appends_every_short_length` |
| hex.rs:307:16 | `/` → `%` | excluded | `hex\.rs:(239:29: replace \* with [+/] in encode_to_string\|307:16: replace / with % in check_rows\|316:(22\|27): replace \* with [+/] in encode_rows\|316:35: replace \+ with \* in encode_rows)\b` |
| hex.rs:316:22 | `*` → `+` | excluded | `hex\.rs:(239:29: replace \* with [+/] in encode_to_string\|307:16: replace / with % in check_rows\|316:(22\|27): replace \* with [+/] in encode_rows\|316:35: replace \+ with \* in encode_rows)\b` |
| hex.rs:316:22 | `*` → `/` | excluded | `hex\.rs:(239:29: replace \* with [+/] in encode_to_string\|307:16: replace / with % in check_rows\|316:(22\|27): replace \* with [+/] in encode_rows\|316:35: replace \+ with \* in encode_rows)\b` |
| hex.rs:316:35 | `+` → `*` | excluded | `hex\.rs:(239:29: replace \* with [+/] in encode_to_string\|307:16: replace / with % in check_rows\|316:(22\|27): replace \* with [+/] in encode_rows\|316:35: replace \+ with \* in encode_rows)\b` |
| hex.rs:316:27 | `*` → `+` | excluded | `hex\.rs:(239:29: replace \* with [+/] in encode_to_string\|307:16: replace / with % in check_rows\|316:(22\|27): replace \* with [+/] in encode_rows\|316:35: replace \+ with \* in encode_rows)\b` |
| hex.rs:316:27 | `*` → `/` | excluded | `hex\.rs:(239:29: replace \* with [+/] in encode_to_string\|307:16: replace / with % in check_rows\|316:(22\|27): replace \* with [+/] in encode_rows\|316:35: replace \+ with \* in encode_rows)\b` |
| hex.rs:324:18 | `>` → `>=` | excluded | `hex\.rs:(324:18: replace > with >= in encode_rows\|359:13: replace > with >= in encode_rows_to_writer\|434:20: replace > with >= in decode_rows\|455:17: replace > with >= in decode_rows)\b` |
| hex.rs:359:13 | `>` → `>=` | excluded | `hex\.rs:(324:18: replace > with >= in encode_rows\|359:13: replace > with >= in encode_rows_to_writer\|434:20: replace > with >= in decode_rows\|455:17: replace > with >= in decode_rows)\b` |
| hex.rs:397:24 | `/` → `%` | killed | `hex::tests::decode_rows_handles_widths_that_do_not_divide_the_scratch` |
| hex.rs:434:20 | `>` → `>=` | excluded | `hex\.rs:(324:18: replace > with >= in encode_rows\|359:13: replace > with >= in encode_rows_to_writer\|434:20: replace > with >= in decode_rows\|455:17: replace > with >= in decode_rows)\b` |
| hex.rs:447:21 | `==` → `!=` | killed | `hex::tests::decode_rows_handles_widths_that_do_not_divide_the_scratch` |
| hex.rs:448:78 | `-` → `+` | killed | `hex::tests::decode_rows_names_a_bad_row_in_a_full_middle_batch` |
| hex.rs:448:78 | `-` → `/` | killed | `hex::tests::decode_rows_names_a_bad_row_in_a_full_middle_batch` |
| hex.rs:455:17 | `>` → `>=` | excluded | `hex\.rs:(324:18: replace > with >= in encode_rows\|359:13: replace > with >= in encode_rows_to_writer\|434:20: replace > with >= in decode_rows\|455:17: replace > with >= in decode_rows)\b` |
| key.rs:22:26 | `\|` → `^` | excluded | `key\.rs:(22:26: replace \\| with \^ in key64\|34:22: replace \\| with \^ in key64_dyn)\b` |
| key.rs:34:22 | `\|` → `^` | excluded | `key\.rs:(22:26: replace \\| with \^ in key64\|34:22: replace \\| with \^ in key64_dyn)\b` |
| ops.rs:55:9 | delete `match arm []` | killed | `ops::tests::a_file_without_records_or_hashes_is_named_as_such` |
| ops.rs:88:46 | `+` → `-` | removed | removed (dead `None` arm of `relayout`) |
| ops.rs:88:46 | `+` → `*` | removed | removed (dead `None` arm of `relayout`) |
| synth.rs:20:16 | `^` → `\|` | killed | `synth::tests::next_u64_matches_the_reference_outputs` |
| synth.rs:20:16 | `^` → `&` | killed | `synth::tests::next_u64_matches_the_reference_outputs` |
| synth.rs:20:21 | `>>` → `<<` | killed | `synth::tests::next_u64_matches_the_reference_outputs` |
| synth.rs:21:16 | `^` → `\|` | killed | `synth::tests::next_u64_matches_the_reference_outputs` |
| synth.rs:21:16 | `^` → `&` | killed | `synth::tests::next_u64_matches_the_reference_outputs` |
| synth.rs:21:21 | `>>` → `<<` | killed | `synth::tests::next_u64_matches_the_reference_outputs` |
| synth.rs:22:16 | `>>` → `<<` | killed | `synth::tests::next_u64_matches_the_reference_outputs` |
| synth.rs:28:9 | body → `0` | killed | `synth::tests::below_takes_the_high_half_of_the_product` |
| synth.rs:28:9 | body → `1` | killed | `synth::tests::below_takes_the_high_half_of_the_product` |
| synth.rs:28:60 | `>>` → `<<` | killed | `synth::tests::below_takes_the_high_half_of_the_product` |
| synth.rs:28:39 | `*` → `+` | killed | `synth::tests::below_takes_the_high_half_of_the_product` |
| synth.rs:28:39 | `*` → `/` | killed | `synth::tests::below_takes_the_high_half_of_the_product` |
| synth.rs:36:12 | delete `!` | killed | `synth::tests::fill_writes_outputs_little_endian` |
| synth.rs:63:5 | body → `vec![]` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:64:43 | `==` → `!=` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:83:21 | `>` → `>=` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:83:84 | `<` → `>` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:83:84 | `<` → `<=` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:96:5 | body → `vec![]` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:96:5 | body → `vec![0]` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:96:5 | body → `vec![1]` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:96:24 | `/` → `%` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:99:10 | `==` → `!=` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:105:31 | `*` → `+` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:105:31 | `*` → `/` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| synth.rs:106:17 | `/` → `%` | killed | `synth::tests::generators_produce_the_traced_outputs` |
| format/chunk.rs:151:9 | body → `Default::default()` | killed | `format::chunk::tests::out_writers_emit_exact_bytes` |
| format/chunk.rs:161:9 | body → `true` | killed | `format::chunk::tests::out_writers_emit_exact_bytes` |
| format/chunk.rs:161:9 | body → `false` | killed | `format::chunk::tests::out_writers_emit_exact_bytes` |
| format/chunk.rs:185:9 | `Out::le_i32` → `()` | killed | `format::chunk::tests::out_writers_emit_exact_bytes` |
| format/chunk.rs:189:9 | `Out::le_i64` → `()` | killed | `format::chunk::tests::out_writers_emit_exact_bytes` |
| format/chunk.rs:227:5 | body → `0` | killed | `format::chunk::tests::out_writers_emit_exact_bytes` |
| format/chunk.rs:227:5 | body → `1` | killed | `format::chunk::tests::out_writers_emit_exact_bytes` |
| format/chunk.rs:227:7 | `+` → `-` | killed | `format::chunk::tests::out_writers_emit_exact_bytes` |
| format/chunk.rs:227:7 | `+` → `*` | killed | `format::chunk::tests::out_writers_emit_exact_bytes` |
| format/decode.rs:90:17 | `match guard (1..=MAX_HINT_BITS).contains(&bits) && rest.len() == BLOCK_ENTRY_LEN << bits` → `true` | killed | `format::decode::tests::hints_with_bad_bits_or_table_length_decode_as_unknown` |
| format/decode.rs:93:17 | `match guard bits <= MAX_HINT_BITS && rest.len() == HULL_ENTRY_LEN << bits` → `true` | killed | `format::decode::tests::hints_with_bad_bits_or_table_length_decode_as_unknown` |
| format/decode.rs:90:53 | `&&` → `\|\|` | killed | `format::decode::tests::hints_with_bad_bits_or_table_length_decode_as_unknown` |
| format/decode.rs:93:39 | `&&` → `\|\|` | killed | `format::decode::tests::hints_with_bad_bits_or_table_length_decode_as_unknown` |
| format/decode.rs:117:18 | `<` → `<=` | killed | `format::decode::tests::a_short_buffer_is_too_short_only_below_the_first_chunk` |
| format/decode.rs:242:20 | delete `!` | killed | `format::decode::tests::filters_are_skipped_inside_a_section_and_rejected_outside` |
| format/encode.rs:63:33 | `\|\|` → `&&` | killed | `format::encode::tests::rejects_ragged_or_zero_length_records` |
| format/encode.rs:99:9 | `+` → `*` | excluded | `encode\.rs:(99:9\|103:62\|103:30): replace \+ with \* in encode\b` |
| format/encode.rs:103:62 | `+` → `*` | excluded | `encode\.rs:(99:9\|103:62\|103:30): replace \+ with \* in encode\b` |
| format/encode.rs:103:30 | `+` → `-` | killed | `format::encode::tests::short_hashes_with_a_record_index_encode` |
| format/encode.rs:103:30 | `+` → `*` | excluded | `encode\.rs:(99:9\|103:62\|103:30): replace \+ with \* in encode\b` |
| format/encode.rs:143:31 | `\|` → `^` | excluded | `encode\.rs:143:31: replace \\| with \^ in encode\b` |
| format/structs.rs:66:9 | body → `0` | killed | `format::structs::tests::derived_lengths` |
| format/structs.rs:66:9 | body → `1` | killed | `format::structs::tests::derived_lengths` |
| format/structs.rs:84:12 | `\|` → `^` | excluded | `structs\.rs:(84:12: replace \\| with \^ in hint_tag_block\|89:12: replace \\| with \^ in hint_tag_hull)\b` |
| format/structs.rs:89:12 | `\|` → `^` | excluded | `structs\.rs:(84:12: replace \\| with \^ in hint_tag_block\|89:12: replace \\| with \^ in hint_tag_hull)\b` |
| format/structs.rs:136:9 | body → `0` | killed | `format::structs::tests::derived_lengths` |
| format/structs.rs:136:9 | body → `1` | killed | `format::structs::tests::derived_lengths` |
| format/structs.rs:136:11 | `+` → `-` | killed | `format::structs::tests::derived_lengths` |
| format/structs.rs:136:11 | `+` → `*` | killed | `format::structs::tests::derived_lengths` |
| format/structs.rs:164:9 | body → `true` | killed | `format::structs::tests::derived_lengths` |
| format/structs.rs:164:9 | body → `false` | killed | `format::structs::tests::derived_lengths` |
| format/structs.rs:164:20 | `==` → `!=` | killed | `format::structs::tests::derived_lengths` |
| hset-cli/main.rs:135:17 | delete `field budget from struct BitsPolicy expression` | killed | `cli::budget_steers_the_chosen_hint_bits` |
| hset-cli/main.rs:302:5 | body → `String::new()` | killed | `cli::info_prints_table_sizes_in_bytes_and_kib` |
| hset-cli/main.rs:302:5 | body → `"xyzzy".into()` | killed | `cli::info_prints_table_sizes_in_bytes_and_kib` |
| hset-cli/main.rs:302:10 | `>=` → `<` | killed | `cli::info_prints_table_sizes_in_bytes_and_kib` |
| hset-cli/main.rs:302:15 | `<<` → `>>` | killed | `cli::info_prints_table_sizes_in_bytes_and_kib` |
| hset-cli/main.rs:304:17 | `>=` → `<` | killed | `cli::info_prints_table_sizes_in_bytes_and_kib` |
| hset-cli/main.rs:304:22 | `<<` → `>>` | killed | `cli::info_prints_table_sizes_in_bytes_and_kib` |
| hset-cli/main.rs:306:17 | `>=` → `<` | killed | `cli::info_prints_table_sizes_in_bytes_and_kib` |
| hset-cli/main.rs:306:22 | `<<` → `>>` | killed | `cli::info_prints_table_sizes_in_bytes_and_kib` |
| hset-cli/main.rs:486:53 | `>` → `==` | killed | `cli::dump_heads_each_section_only_when_there_are_several` |
| hset-cli/main.rs:486:53 | `>` → `<` | killed | `cli::dump_heads_each_section_only_when_there_are_several` |
| hset-cli/main.rs:486:53 | `>` → `>=` | killed | `cli::dump_heads_each_section_only_when_there_are_several` |
| hset-cli/main.rs:577:59 | `*` → `/` | killed | `cli::query_records_prints_each_match_and_the_misses` |
| hset-cli/main.rs:584:23 | delete `!` | killed | `cli::query_records_prints_each_match_and_the_misses` |
| hset-cli/main.rs:664:21 | delete `field budget from struct BitsPolicy expression` | killed | `cli::budget_steers_the_chosen_hint_bits` |
| hset-cli/main.rs:804:19 | `==` → `!=` | killed | `cli::bench_single_only_times_single_lookups` |
| ops.rs:110:19 | `+=` → `*=` | timeout (detected) | - |
| ops.rs:116:19 | `+=` → `*=` | timeout (detected) | - |
| format/chunk.rs:101:18 | `+=` → `*=` | timeout (detected) | - |

## 4. Operational notes

Three attempts were needed to get a complete hset mutants run, each exposing a defect in the
Task 17 `mutants` recipe that got fixed in place:

1. **01:55, failed at the baseline.** `just mutants hset` (and `hset-cli`) failed before
   testing any mutant: `hset::fixtures::{all_fixtures_decode_and_verify,
   good_hset_matches_reference_expectations}` and three `hset-cli::cli` tests resolve the
   C++-generated fixtures as `CARGO_MANIFEST_DIR/../../test`, which is outside the `rust/`
   workspace that cargo-mutants copies into a per-job tempdir. Fixed by adding
   `hset_testkit::fixtures_dir()`, which returns `$HSET_FIXTURES_DIR` at runtime when set and
   falls back to the old relative path otherwise; the `mutants`/`mutants-diff` recipes export
   `HSET_FIXTURES_DIR` as an absolute path to the real `test/` directory. Commit 8a4ef6c.
2. **02:28, aborted at 751/1905.** With the fixture fix in place, the run (6 GiB
   `systemd-run --user --scope` cap, `-j 2`) got through 751 of 1905 hset mutants (585 caught,
   81 missed, 1 timeout, 84 unviable, per `hset-run1.log`) before the mutant
   `ops.rs:110 replace += with *= in merge` turned a bounded loop into one that appends rows
   forever; the union test it ran under grew to 2.8 GB, the 6 GiB scope hit its memory cap, and
   systemd's default `OOMPolicy` for the scope stopped the *whole* unit, so cargo-mutants
   itself was killed mid-run and reported `interrupted`. hset-cli, run as a separate job right
   after, completed cleanly in the few minutes before the resume (136 mutants: 41 caught, 16
   missed, 0 timeout, 79 unviable). Fixed by adding `-p OOMPolicy=continue` to the recipe's
   `systemd-run` scope, so the kernel OOM killer removes only the runaway mutant's test
   process (which nextest then reports as a failure, i.e. the mutant counts as caught) instead
   of systemd tearing down the whole scope. Commit 574f3c9.
3. **04:40-09:44, resumed with `--iterate`.** The hset run restarted with `--iterate`, which
   skips the 669 mutants already resolved as caught or unviable in the aborted run and retests
   everything else: the previous run's 82 missed/timeout outcomes plus the 1154 mutants never
   reached, 1236 in total (`hset-run2.log`: "1236 mutants tested in 5h: 332 missed, 823 caught,
   49 unviable, 32 timeouts"). Wall time 5 h 4 min. Merging run 1's 669 resolved outcomes with
   run 2's 1236 gives the final hset totals in section 1 (669 + 1236 = 1905; caught
   585 + 823 = 1408, unviable 84 + 49 = 133, and all 332 missed / 32 timeout come from run 2
   since run 1's missed/timeout mutants were re-tested rather than kept).

Confirmation runs during triage (re-checking each proposed kill or exclusion against then-HEAD)
used the capped form `systemd-run --user --scope -p MemoryMax=6G -p MemorySwapMax=0
-p OOMPolicy=continue cargo mutants --package <pkg> -j 2 -F <regex> --output
target/mutants-confirm/<run>`, the same cap and concurrency as the full runs.

## 5. Bugs found by every tier

No tier run during Task 18 itself found a bug: `just prop` (20,000 cases, 186 tests, 2021 s),
`just fuzz-ci` plus two 1200 s bounded long runs (lookup, corrupt_doc), `just verify` (29 Kani
harnesses, 507 s), and the mutation run and its triage were all clean (see
`task-18a-report.md` and sections 1-2 above). Across the whole deep-testing plan, nine bugs
were found and fixed, all by the property-test and fuzzing tiers (none by Kani or mutation
testing); from `.superpowers/sdd/2026-10-02-rust-deep-testing/progress.md`'s `BUG FOUND+FIXED`
ledger lines:

| task | tier | bug | regression commit | fix commit |
|---|---|---|---|---|
| 6 | `prop_format.rs` (property) | `hull.rs` `fit_block` residual `as i32` wrap excluded a block's own hashes from its window | c942eab | f2c4f5e |
| 7 | `prop_lookup.rs` (property) | k-ary single search looped forever when `window_prefetch_bytes` < 8 hashes (KAry, Auto, and Recursive's fallback) | 73d8eec | 4406eb9 |
| 11 | `prop_cli.rs` (property, CLI oracle) | CLI rejected hyphen-leading `-n`/`-d` values | 4e8c54a | 5de8e51 |
| 11 | `prop_cli.rs` (property, CLI oracle) | CLI query rejected negative numeric values | 62df2f7 | 557667b |
| 12 | in-crate proptest (`hash_type`) | `HashType::parse` rejected the display name "Quick MD5" (the C++ reference's `hash_types.cpp` accepts "quick md5") | e9fefbf | 7e384ee |
| 13 | in-crate proptest (`format::chunk`) | `Cursor::pstring` advanced its position on a failed body read | 09810b0 (regression), c96338c (test correction) | f3a6b04 |
| 14 | fuzzing | flat block model arithmetic overflow on corrupt hint bounds | 8157d50 | 6ef42cc |
| 14 | fuzzing | flat block hint centred near `i64::MIN` overflowed the region-radius sample's `index - centre` | 67981e2 | f97c45a |
| 14 | fuzzing | `add_text_line` stripped every trailing CR/LF instead of one line ending | 7030dd0 | ea85572 |
| 14 | fuzzing | test kit's `exercise_loaded` aborted allocating a query of an absurd `hash_length` for an empty section | d2eaa8c | 76a0783 (kit-side fix) |

Two further issues were found but parked for the final whole-branch review rather than fixed
mid-plan: `lookup::hull::choose_slope` discards slopes above 1 instead of capping them (Task
12; not a soundness bug, just wider but still-correct windows on clustered inputs), and
`ops::relayout` matches record fields by hash type only, so a file listing the same type
twice with different lengths copies bytes from the wrong field — silent wrong output on a
file with duplicate field types; it matches the C++ reference's own behaviour, so this is
parity rather than a regression, and is left as a follow-up (Task 18b-2 implementer note; no
survivor pointed at it, and the correct semantics depend on the C++ reference).

## 6. Final gate

`cd rust && just check`: green (`cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --
-D warnings`, then `just test`), exit 0, 237 tests passed, 0 skipped.

`just test` alone, warm, nothing else running on the VM: **24.4 s** (`cargo nextest run
--workspace` 22.2 s + `cargo test --workspace --doc` under the same invocation), under the
plan's 30 s budget.
