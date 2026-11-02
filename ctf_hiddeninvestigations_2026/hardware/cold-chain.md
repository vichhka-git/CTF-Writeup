# Cold Chain

Hardware, 69 points, 163 solves. A supermarket refrigeration controller, a ColdLink CaseManager CM-900, has driven all six refrigerated cases into continuous defrost. You get a network session to the controller and the vendor's technician toolkit. The job is to authenticate, find what is forcing defrost, remove it in a way that survives the controller's own automation, hold all six cases under the compliance ceiling for the full window, and collect the proof that `STATUS` releases.

## What you are given

`cold-chain.zip` contains `coldlink_tech.py` (field technician client), `CLMP_reference.md` (the CLMP/1.1 protocol reference), and `historian_sample.log` (an illustrative overnight export). There is no flag in the archive.

The portal supplies two endpoints for your team's instance: a control service and a read-only historian feed, each as `<challenge-host>` and `<port>`. Both are TLS-terminated and routed by SNI, so the endpoint's own hostname has to be presented as the SNI name. `CLMP_reference.md` states this explicitly. Nothing in the archive gives the host or the ports; they exist only on the challenge page for your lease.

There is no solution document in the local challenge directory. The account below is reconstructed from the live session log and the team's submission record, both in the workspace, plus the shipped reference.

## Reproduction

1. Read `CLMP_reference.md` first. CLMP/1.1 is line-oriented UTF-8 over TCP, `\n` terminated. On connect the controller sends a greeting and then waits:

   ```
   CLMP/1.1 ColdLink CaseManager CM-900
   SERIAL <serial>
   NONCE <32 hex>
   READY
   OK greeting
   ```

   Every command answers with zero or more `DATA ...` lines and one terminal `OK` or `ERR` line, so a client reads until that terminal line. `QUIT` closes. All commands except `AUTH`, `HELP`, `PING`, `QUIT` return `ERR need-auth` before authentication.

2. Work out the authentication. `coldlink_tech.py` carries the fleet "field master key" as a constant and derives the answer to the greeting with it:

   ```python
   material = "<field master key>|<serial>|<nonce>"
   token = hashlib.sha256(material.encode()).hexdigest()[:16]
   ```

   The key value is not reproduced here; it is the constant provisioned in the toolkit source, and the challenge notes treat it as a service credential. The command form is `AUTH <serial> <token>`. Success returns `OK role=technician`; anything else returns `ERR bad-auth`.

3. Connect. Either drive the protocol by hand over TLS with SNI, or bridge the plain-TCP toolkit through a local tunnel:

   ```
   openssl s_client -quiet -connect <challenge-host>:<port> -servername <challenge-host>
   socat TCP-LISTEN:7601,reuseaddr,fork OPENSSL-CONNECT:<challenge-host>:<port>,snihost=<challenge-host>
   ```

   Plain `nc` to the hosted endpoint does not connect, because SNI decides which instance you reach. Note that the reference document's default port numbers (7601 control, 7602 historian) are device defaults; the hosted instance uses the ports the portal assigned.

4. Authenticate and read the state. `CASES` shows the damage: six cases, `DAIRY-1`, `PRODUCE-2`, `MEAT-3`, `FROZEN-4`, `DELI-5`, `BEVERAGE-6`, all at `temp=12.00 set=2.0 mode=defrost trip=0`. Nothing is holding temperature because every case is being heated.

   ```
   > AUTH <serial> <token>
   OK role=technician
   > CASES
   DATA case=1 name=DAIRY-1 temp=12.00 set=2.0 mode=defrost trip=0
   ```

5. List the standing rules and the maintenance automation. Both matter, and the reference document gives them separate sections for a reason.

   ```
   > SCHED LIST
   DATA sched=S1 name=DAYTIME_COOL action=cool_all enabled=1
   DATA sched=S3 name=NIGHT_SETBACK action=cool_all enabled=1
   DATA sched=S9 name=WINTER_DEFROST_ALL action=force_defrost enabled=1
   > MACRO LIST
   DATA macro=M1 name=DAILY_SELFTEST enabled=1 period=3600 action=noop
   DATA macro=M2 name=AUTO_WINTERIZE enabled=1 period=90 action=ensure_schedule
   ```

   `S9` is the thing forcing defrost. `M2` runs every 90 seconds with action `ensure_schedule`, which the reference defines as "re-enable the macro's target schedule if a technician disabled or removed it". `MACRO GET M2` confirms `target=S9`, note `re-applies_seasonal_defrost_schedule`.

6. Check the mechanism against the historian export before changing anything. The shipped sample is illustrative, and its own header says the live feed will differ, but it shows the controller's view of the loop:

   ```
   seq=4 ts=60.0 event=macro_apply macro=M2 schedule=S9 detail=re-enabled_forced_defrost
   seq=8 ts=161.5 event=sched_deleted schedule=S9
   seq=9 ts=240.0 event=macro_apply macro=M2 schedule=S9 detail=re-enabled_forced_defrost
   ```

   A schedule deletion is followed by another macro apply, and an operator note in the same export reads `disabled_S9_again_but_it_keeps_coming_back`. The recorded live run did not tail the live feed; the log contains no historian records, and the conclusion came from `MACRO GET M2` alone. The feed is worth connecting if you want the timeline, since it is unauthenticated and read-only.

7. Repair in the right order. Disable the macro first, then neutralise the schedule. Doing it the other way leaves a window in which `M2` re-enables `S9` before you get to it.

   ```
   > MACRO DISABLE M2
   OK macro=M2 enabled=0
   > SCHED SET S9 enabled=0 action=noop
   OK sched=S9 enabled=0 action=noop
   ```

   `SCHED SET S9 enabled=0` alone would stop the defrost, but `M2` would turn it back on within its 90 second period. The action is also set to `noop` so the entry cannot re-assert defrost if it is ever enabled again.

8. Verify the repair is durable. Re-read both records:

   ```
   > MACRO GET M2
   DATA macro=M2 name=AUTO_WINTERIZE enabled=0 period=90 action=ensure_schedule target=S9 ...
   > SCHED GET S9
   DATA sched=S9 name=WINTER_DEFROST_ALL action=noop enabled=0 ...
   ```

   Both show the change and nothing else has been touched. `S1` and `S3` stay enabled and keep driving the cases to their 2.0 C setpoint. Manual `MODE <case> cool` overrides were not needed and were not used; the reference says a manual override does not stick while an enabled schedule re-asserts modes, so the schedule layer is the correct place to fix this.

9. Watch the hold window. The compliance ceiling is 5 C and the required sustained hold is 60 seconds, both from the reference. Poll `CASES` and `STATUS` through the whole window; the recorded run polled about every 5 seconds for 65 seconds. The progression, with the interesting values:

   ```
   poll 1   DATA compliant=0 cases_cold=0/6 held=0s reason=cases_above_5C=6
   poll 2   DATA case=1 ... temp=3.39 set=2.0 mode=cool trip=0
            DATA compliant=0 cases_cold=6/6 held=3s reason=holding_3/60s
   poll 12  DATA case=6 ... temp=2.66 set=2.0 mode=cool trip=1
            DATA compliant=0 cases_cold=6/6 held=58s reason=holding_58/60s
   poll 13  DATA compliant=1 cases_cold=6/6 held=63s
            DATA flag=hiCTF{...}
   ```

   The cases still read 12.00 on the first poll after the repair, then 3.39 on the next, and settle between 2.31 and 2.6. A compressor trip flag appears on `BEVERAGE-6` at poll 12 and clears by poll 13 without resetting the hold counter, so a transient trip during the window does not restart it.

10. `STATUS` on the final poll returns `compliant=1`, `cases_cold=6/6`, `held=63s` with no `reason=` field, and then a separate `DATA flag=` line. The flag line is only emitted on full compliance.

## Why it works

The controller has two independent layers that can drive case modes: the schedule table, which a technician edits, and maintenance macros, which run on their own timers. `AUTO_WINTERIZE` is a seasonal convenience macro whose only function is to re-enable the defrost schedule if someone disables or deletes it. That makes the obvious remediation (disable the defrost schedule) ineffective, and it makes the failure look like a stubborn controller rather than like a second writer that the operator never configured.

The design mistake is the combination: a macro that can resurrect a schedule indefinitely, with no interlock against a human service action, plus a compliance check that only issues proof after a sustained hold. Fixing `S9` without disabling `M2` leaves the system in a loop where defrost returns every 90 seconds. Disabling `M2` first and retiring `S9` (enabled off, action `noop`) removes both writers, after which the surviving cooling schedules hold the cases under the ceiling for the full window.

## Flag

```
hiCTF{cold_chain_restored_defrost_cleared_7dbe44e9ca}
```
