# Don't consider the HTTPS hostname since the enforced HTTPS redirection should
# work if the SSL check skipped.  See file docker/healthcheck.sh.
/http/ {
  getline;
  print "http://" $2;
}
