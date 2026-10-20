match($0, /[0-9]+%;/) {
  value = substr($0, RSTART, RLENGTH - 2)
  print value
  exit
}
