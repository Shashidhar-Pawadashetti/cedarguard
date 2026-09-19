// Default permit — required by Cedar so that forbid policies can meaningfully
// override. Without this, every authorization would be DENY by default (no
// policy matches → implicit deny), and the per-rule forbid policies couldn't
// distinguish "explicitly forbidden" from "no rule matched".
permit (
  principal,
  action,
  resource
);
