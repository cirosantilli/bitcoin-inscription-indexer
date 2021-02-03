#!/usr/bin/env bash
set -eu
readme=README.adoc
sed -Ei "/^Here is the index of files:$/q" "$readme"

printf "\n=== Inputs index\n\n" >> "$readme"
n="$(ls data/in | tail -n1 | sed -r 's/0*//;s/.txt//')"
i=0
while (( $i <= $n )); do
  f="$(printf data/in/%04d.txt "$i")"
  printf "* link:$f[] ($(du -sh "$f" | cut -f1))\n" >> "$readme"
  i=$(($i + 1))
done

printf '\n=== Outputs index\n\n' >> "$readme"
i=0
while (( $i <= $n )); do
  f="$(printf data/out/%04d.txt "$i")"
  printf "* link:$f[] ($(du -sh "$f" | cut -f1))\n" >> "$readme"
  i=$(($i + 1))
done

printf "\n=== Atomsea index\n\n" >> "$readme"
sed -r 's/^/* http:\/\/bitfossil.org\//' data/atomsea >> "$readme"
