BEGIN {
  FS = "'"
}

/Now drawing from/ {
  print $2
  exit
}
