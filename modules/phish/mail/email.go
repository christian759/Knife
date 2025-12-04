package mail

import "gopkg.in/gomail.v2"

type Email struct {
	Heading string
	From    string
	To      string
	Cc      string
	Body    string
}

func (*Email) setAttributeEmail(heading string, from string, to string, cc string, body string) {
	// Setting email attributes
}

func sendEmail(email *Email) error {
	m := gomail.NewMessage()

	m.SetHeader("From", email.From)
	m.SetHeader("To", email.To)
	m.SetHeader("Subject", email.Heading)
	m.SetBody("text/plain", email.Body)

	d := gomail.NewDialer("smtp.gmail.com", 465, email.From, "your-app-password")

	if err := d.DialAndSend(m); err != nil {
		panic(err)
	}

	println("Email sent successfully!")
	return nil
}
