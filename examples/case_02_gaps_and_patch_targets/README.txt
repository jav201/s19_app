Case 02: Contains clear gaps and explicit patch targets.
Suggested tests:
  patch-str --addr 0x80010005 --text "05182025"
  patch-hex --addr 0x80010080 --bytes "DE AD BE EF"
