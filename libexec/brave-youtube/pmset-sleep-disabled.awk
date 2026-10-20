/SleepDisabled/ {
  print $2
  found = 1
  exit
}

END {
  if (!found) {
    print 0
  }
}
