module github.com/kiebitz-oss/services

go 1.13

require (
	github.com/go-redis/redis v6.15.9+incompatible
	github.com/kiprotect/go-helpers v0.0.0-20210706144641-b74c3f0f016d
	github.com/sirupsen/logrus v1.8.1
	github.com/urfave/cli v1.22.5
	gopkg.in/yaml.v2 v2.2.2
)

// replace github.com/kiprotect/go-helpers => ../../../geordi/kiprotect/go-helpers
