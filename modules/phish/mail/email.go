package mail

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
