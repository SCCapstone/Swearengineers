#!/usr/bin/env python
from google.appengine.api import mail

WEBSENDER='MathQuizzes<MathQuizzes@math-quizzes-jesager.appspotmail.com>',

def sendit():
  course_name='Math 101'
  quiz_name='Quiz 14'
  quiz_description='Subtraction'
  if quiz_description:
    quiz_name=quiz_name + ':  ' + quiz_description
  quiz_url='http://www.google.com'
  instructor='Smith'
  first='James'
  last='Sager'
  email='jamessager@hotmail.com'
  address=first + ' ' + last + '<' + email + '>'

  subject='New Quiz from Instructor' + instructor

  message = mail.EmailMessage(WEBSENDER, subject)
  message.to = address

  message.body = """
    Hi, """ + first + '!'+ """

    Instructor """ + instructor + """ has assigned you """ + quiz_name + """
    through your MathQuizzes """ + course_name + """ Course.

    Paste the linke below into your browser to start the quiz:

    """+ quiz_url +"""

    Best of luck from the MathQuizzes Team!
  """

  message.html = """
    <html>
    <body style="margin:0;padding:0;
      font-family:'Helvetica Neue', Helvetica, Arial, sans-serif;">
      <div
        style="background:#222;padding:1%;
        border-bottom: 10px solid #5bc0de">
        <h2 style="font-weight:normal; color:#FFF; padding-left:2%; margin:2px 0;">
          <span style="color:#5bc0de">Math</span>Quizzes
        </h2>
      </div>
      <div style="padding: 0 3%; border-bottom:1px solid #CCC">
        <h2 style="font-weight:normal">Hi, """+ first +"""!</h2>
        <p>Instructor """+ instructor +""" just assigned you """+ quiz_name +"""
           through your MathQuizzes """ + course_name + """ Course.</p>
        <p>Click the link below to start your quiz:</p>
        <h2 style="color:#3378b7;padding-left:10%;font-weight:normal">
          <a href='""" + quiz_url + """' title="Take the Quiz!"
            style="color:#3378b7;">""" + quiz_name + """</a></h2>
        <br>
        <h3 style="font-weight:normal">Best of luck from the MathQuizzes Team!</h3>
        <br>
        <br>
      </div>
    </body>
    </html>
  """

  message.send()




