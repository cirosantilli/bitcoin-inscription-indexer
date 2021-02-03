#!/usr/bin/env bash
tail -n+1 "$@" \
  | grep -Piv '^$' \
  | grep -Piv '^tx ' \
  | grep -Piv '/BW Pool/' \
  | grep -Piv 'BW Support 8M' \
  | grep -Piv '^id[:;]' \
  | grep -Piv '{"expire":' \
  | grep -Piv 'https://arbx.co' \
  | grep -Piv '^http://www.blockcypher.com' \
  | grep -Piv 'https://cpr.sm' \
  | grep -Piv 'mined by' \
  | grep -Piv 'ASCRIBESPOO' \
  | grep -Piv 'usersusersusers' \
  | grep -Piv '50BTC.com' \
  | grep -Piv '^.?/P2SH/' \
  | grep -Piv '^.?EclipseMC: ' \
  | grep -Piv ' /P2SH/$' \
  | grep -Piv '/SockThing/' \
  | grep -Piv 'feeds.info/static/live' \
  | grep -Piv '^.?BBTCChina Pool' \
  | grep -Piv '^.?.?u=http' \
  | grep -Piv '^503: Bitcoin over capacity!' \
  | grep -Piv '! xcp.com/feed' \
  | grep -Piv '! t.io/feed' \
  | grep -Piv 'https://live.blockcypher' \
  | grep -Piv '[a-zA-Z0-9+/]+=?=$' \
  | grep -Piv '^j.[[:digit:]]+$' \
  | grep -Piv '^.?j.?[[:digit:]abcdef]+$' \
  | grep -Piv 'Bitcoin: A Peer-to-Peer Electronic Cash System' \
  | grep -Piv '/BTCC/' \
  | grep -Piv ';ORIGMY$' \
  | grep -Piv '/NYA/$' \
  | grep -Piv '/BTC.TOP/$' \
  | grep -Piv '^[a-zA-Z0-9]+$' \
  | grep -Piv '@COPYROBO@' \
  | grep -Piv '@PROOFSTACK@' \
  | grep -Piv '\*\* PROOF.COM \*\*' \
  | grep -Piv 'https://codepen.io/anon/pen/pVKajz\?editors=0011' \
  | grep -Piv 'https://codepen.io/anon/pen/yjMKXv\?editors=1011' \
  | grep -Piv '{"ver":1' \
  | grep -Piv '"auth":"0"' \
  | grep -Piv ',[a-f0-9]{65}' \
  | grep -Piv 'BTCKEY\.' \
  | grep -Piv 'ChainX:' \
  | grep -Piv 'bitcoin@protonmail.com' \
;
