package client

import (
	"io/ioutil"
	"path"

	"github.com/juju/errors"
	"github.com/sirupsen/logrus"
)

var (
	logger = logrus.WithField("mode", "webroot")
)

type WebRootChallengeResponder struct {
	rootPath string
}

func NewWebRootChallengeResponder(rootPath string) (*WebRootChallengeResponder, error) {
	cr := WebRootChallengeResponder{rootPath: rootPath}
	return &cr, nil
}

func (h *WebRootChallengeResponder) SetResource(p, resource string) {
	l := logger.WithFields(logrus.Fields{"path": p, "resource": resource})
	l.Debugln("SetResource")

	resPath := path.Join(h.rootPath, p)
	if err := ioutil.WriteFile(resPath, []byte(resource), 0755); err != nil {
		l.Error(errors.Annotate(err, "write ressource"))
	}
}
