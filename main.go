package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Config struct {
	User               string
	Passwd             string
	Identity           string
	IdentityFile       string
	IdentityPassphrase string
	Host               string
	Port               int
	TotpSecret         string
}

func (c Config) GetUser() string {
	if c.User != "" {
		return c.User
	}
	u, _ := user.Current()
	c.User = u.Username
	return c.User
}

func (c Config) GetIdentity() (ssh.Signer, error) {
	if c.IdentityFile != "" {
		homeDir, err := os.UserHomeDir()
		var isHome bool
		if err == nil {
			filename := filepath.Join(homeDir, ".ssh", c.IdentityFile)
			_, err := os.Stat(c.IdentityFile)
			if err == nil {
				c.IdentityFile = filename
				isHome = true
			}
		}
		if !isHome {
			_, err = os.Stat(c.IdentityFile)
			if err != nil {
				return nil, err
			}
		}
		f, err := os.Open(c.IdentityFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		bs, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		c.Identity = string(bs)
	}
	if len(c.Identity) < 1 {
		return nil, nil
	}
	if len(c.IdentityPassphrase) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(c.Identity), []byte(c.IdentityPassphrase))
	}
	return ssh.ParsePrivateKey([]byte(c.Identity))
}

func main() {
	var config Config
	flag.StringVar(&config.User, "l", "", "login name")
	flag.StringVar(&config.Host, "h", "127.0.0.1", "remote host")
	flag.IntVar(&config.Port, "p", 22, "remote port")
	flag.StringVar(&config.IdentityFile, "i", "", "identity file ($HOME/.ssh/)")
	flag.StringVar(&config.TotpSecret, "s", "", "totp secret")
	flag.Parse()

	conf := ssh.ClientConfig{
		User:            config.GetUser(),
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 5,
	}

	if config.Passwd != "" {
		conf.Auth = append(conf.Auth, ssh.Password(config.Passwd))
	}

	v, err := config.GetIdentity()
	if err != nil {
		log.Fatalf("parse identity: %s", err)
	}
	if v != nil {
		conf.Auth = append(conf.Auth, ssh.PublicKeys(v))
	}

	if config.TotpSecret != "" {
		conf.Auth = append(conf.Auth, ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) (answers []string, err error) {
			totpOption := totp.ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			}
			now := time.Now()
			if now.Unix()%int64(totpOption.Period) > int64(totpOption.Period-2) {
				time.Sleep(5 * time.Second)
				now = time.Now()
			}
			v, err := totp.GenerateCodeCustom(config.TotpSecret, now, totpOption)
			if err != nil {
				return nil, err
			}
			return []string{v}, nil
		}))
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", config.Host, config.Port), &conf)
	if err != nil {
		log.Fatalf("dial ssh: %s", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("new session: %s", err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		log.Fatalf("terminal make raw: %s", err)
	}
	defer term.Restore(fd, state)

	w, h, err := term.GetSize(fd)
	if err != nil {
		log.Fatalf("terminal size: %s", err)
	}

	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err = session.RequestPty(term, w, h, modes); err != nil {
		log.Fatalf("session request pty: %s", err)
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	if err := session.Shell(); err != nil {
		log.Fatalf("session shell: %s", err)
	}

	if err = session.Wait(); err != nil {
		log.Fatalf("session wait: %s", err)
	}
}
