// Copyright (C) 2021 - 2022 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package akcss

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/smtp"

	"github.com/iDigitalFlame/akcss/xerr"
)

var mailer = &net.Dialer{Timeout: timeout, KeepAlive: timeout, DualStack: true}

type mail struct {
	To      string
	Body    string
	Subject string
}

func (m *manager) mail(e mail) error {
	if len(e.Body) == 0 || len(e.Subject) == 0 {
		m.log.Warning("[daemon/mailer] Skipping invalid email queue item, empty body or subject!")
		return nil
	}
	if len(e.To) == 0 {
		return xerr.New("could not send email: empty to")
	}
	r := m.Config.Email.From
	if len(r) == 0 {
		r = m.Config.Email.Username
	}
	if len(r) == 0 {
		return xerr.New("could not send email: empty sender")
	}
	var (
		x, f   = context.WithTimeout(context.Background(), timeout)
		s, err = mailer.DialContext(x, "tcp", m.Config.Email.Host)
	)
	m.log.Trace("[deamon/mailer] Connecting to mail host %q...", m.Config.Email.Host)
	if f(); err != nil {
		return xerr.Wrap(`could not connect to "`+m.Config.Email.Host+`"`, err)
	}
	var (
		h, _, err2 = net.SplitHostPort(m.Config.Email.Host)
		c          *smtp.Client
	)
	if err2 != nil {
		return xerr.Wrap(`unable to parse "`+m.Config.Email.Host+`"`, err)
	}
	if c, err = smtp.NewClient(s, h); err != nil {
		return xerr.Wrap(`unable to establish a valid connection to "`+h+`"`, err)
	}
	defer c.Close()
	if err = c.Hello(h); err != nil {
		return xerr.Wrap(`mailer "`+h+`" HELLO command failed`, err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(&tls.Config{ServerName: h}); err != nil {
			return xerr.Wrap(`mailer "`+h+`" TLS setup failed`, err)
		}
	}
	if len(m.Config.Email.Username) > 0 || len(m.Config.Email.Password) > 0 {
		m.log.Debug("[deamon/mailer] Logging into mail host %q as %q...", h, m.Config.Email.Username)
		if err = c.Auth(smtp.PlainAuth(m.Config.Email.Username, m.Config.Email.Username, m.Config.Email.Password, h)); err != nil {
			return xerr.Wrap(`mailer "`+h+`" authentication failed`, err)
		}
	}
	if err = c.Mail(r); err != nil {
		return xerr.Wrap(`mailer "`+h+`" FROM command failed`, err)
	}
	if err = c.Rcpt(e.To); err != nil {
		return xerr.Wrap(`mailer "`+h+`" RCPT command failed`, err)
	}
	var w io.WriteCloser
	if w, err = c.Data(); err != nil {
		return xerr.Wrap(`mailer "`+h+`" DATA command failed`, err)
	}
	_, err = w.Write([]byte(
		"To: " + e.To + "\r\nFrom: Akcss VPN <" + r + ">\r\nSubject: " + e.Subject + "\r\n\r\n" + e.Body + "\r\n",
	))
	if err != nil {
		return xerr.Wrap(`mailer "`+h+`" body writing failed`, err)
	}
	if err = w.Close(); err != nil {
		return xerr.Wrap(`mailer "`+h+`" body close failed`, err)
	}
	if err = c.Quit(); err != nil {
		return xerr.Wrap(`mailer "`+h+`" quit command failed`, err)
	}
	return nil
}
func (m *manager) mailer(x context.Context) {
	m.log.Info("[daemon/mailer] Stating mailer thread...")
	for {
		select {
		case <-x.Done():
			m.log.Info("[daemon/mailer] Stopping mailer thread.")
			return
		case e := <-m.deliver:
			m.log.Debug("[daemon/mailer] Received email to send to %q...", e.To)
			if err := m.mail(e); err != nil {
				m.log.Warning("[daemon/mailer] Could not send email to %q: %s!", e.To, err.Error())
			}
			m.log.Debug("[daemon/mailer] Completed email request to %q...", e.To)
		}
	}
}
func (m *manager) Mail(to, subject, body string) {
	if len(m.Config.Email.Host) == 0 {
		return
	}
	select {
	case m.deliver <- mail{To: to, Subject: subject, Body: body}:
	default:
	}
}
