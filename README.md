Net-Abuse-Reporter
==================

An attempt to make network abuse reporting easier

One of the big problems in network abuse handling is that the victims seldom know how to report it, and even if they do know, they're faced with the daunting task of implementing their own solution on an RFC by RFC basis.

This Perl bundle attempts to take all the hard work out of your hands, by smooshing together the "obvious" APIs for various RFCs into one coherent, simple API.

At it's most minimal, the API consists of just three methods:

`$reporter = Net::Abuse::Reporter->new()` creates and prepares a reporting engine.

`$reporter->add_incident($logs)` absorbs the logs for one "incident", e.g.

 * the full headers & body of a SPAM email
 * one log entry from Apache, IPTables, Fail2ban, etc
 * a packet trace of one network event (intrusion attempt, DDoS reflection, etc)

`$reporter->send_reports()` groups the incidents by responsible ASN / ISP, finds the right abuse@ contact, finds the right RFC (or other standard) to report each incident in, and sends email(s) to each abuse@ contact detailing the incidents.

It's made of plugins
--------------------

The `add_incident` and `send_report` methods are entirely pluggable (assuming the plugins adhere to the expected APIs). This allows you to write your own log format readers, and abuse report writers, either for proprietary use, or to release into the wild.
