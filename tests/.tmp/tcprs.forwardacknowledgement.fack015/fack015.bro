@TEST-EXEC: bro -C -r ${TRACES}/tcp/forwardacknowledgement/fack015.trace Bro/TCPRS
@TEST-EXEC: btest-diff conn.log
@TEST-EXEC-FAIL: test -f tcpreordering.log
@TEST-EXEC: btest-diff tcpdeadconnection.log
@TEST-EXEC: btest-diff tcprecovery.log
@TEST-EXEC: btest-diff tcpretransmissions.log
@TEST-EXEC: btest-diff tcpoptions.log

