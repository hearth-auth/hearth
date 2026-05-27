module github.com/anthropics/hearth/examples/go-gin

go 1.26.3

require (
	github.com/anthropics/hearth/sdks/go v0.0.0
	github.com/gin-gonic/gin v1.10.0
	github.com/lestrrat-go/jwx/v2 v2.1.3
)

replace github.com/anthropics/hearth/sdks/go => ../../sdks/go
