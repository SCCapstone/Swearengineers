#!/usr/bin/env python
from google.appengine.api import mail

#    mail.send_mail(
#      sender = 'MathQuizzes<MathQuizzes@math-quizzes-jesager.appspotmail.com>',
#      to = 'James <jamessager@hotmail.com>',
#      subject = "Testing",
#      body = """
#      <h1>Hi!</h1>
#      Test test test.
#      """+'<h3>another</h3>'
#    )

def sendit():
  message = mail.EmailMessage(
    sender='MathQuizzes<MathQuizzes@math-quizzes-jesager.appspotmail.com>',
    subject="MSG TEST")
  message.to = "James Sager <jamessager@hotmail.com>"

  message.body = """
  Dear Albert:

  Your example.com account has been approved.  You can now visit
  http://www.example.com/ and sign in using your Google Account to
  access new features.

  Please let us know if you have any questions.

  The example.com Team
  """

  message.html = """
  <html><head></head><body>
  <h1>Dear Albert:<h1>

  Your example.com account has been approved.  You can now visit
  http://www.example.com/ and sign in using your Google Account to
  access new features.

  <b>Please</b> let us know if you have any questions.

  The example.com Team
  </body></html>
  """

  message.send()
