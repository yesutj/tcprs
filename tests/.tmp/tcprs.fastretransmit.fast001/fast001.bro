@TEST-EXEC: bro -C -r ${TRACES}/tcp/fastretransmit/fast001.trace Bro/TCPRS
@TEST-EXEC: btest-diff conn.log
@TEST-EXEC-FAIL: test -f tcpreordering.log
@TEST-EXEC-FAIL: test -f tcpdeadconnection.log
@TEST-EXEC: btest-diff tcpretransmissions.log
@TEST-EXEC: btest-diff tcpoptions.log
@TEST-EXEC: btest-diff tcprecovery.log

