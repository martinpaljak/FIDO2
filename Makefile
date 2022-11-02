default:
	./mvnw -T1C clean verify
fast:
	./mvnw -T1C install -Dmaven.test.skip=true -Dspotbugs.skip=true
	
