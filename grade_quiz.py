#!/usr/bin/env python
from main import *
from sympy import *
from sympy.parsing.sympy_parser import parse_expr
from sympy.parsing.sympy_parser import standard_transformations,\
  implicit_multiplication_application

################################################################################
# Function:  Grade Quiz
#   - Called from the class inQuizzesHandler in main.py
#   - Grades / Records / Shows Results
################################################################################
def grade_quiz(self, user_key, Author, Problem, Quiz, Result):

  posted=self.request.POST.items()
  courseUrl=self.user.selectedCourseKey
  course = ndb.Key(urlsafe=courseUrl).get()
  quiz=ndb.Key(urlsafe=course.selectedQuizKey).get()
  transformations = (standard_transformations +
    (implicit_multiplication_application,))
  good=0
  problems=[]
  solutions=[]
  answers=[]
  grades=[]

  for p in posted:
    if not p[1]:
      answers.append('blank')
    else:
      answers.append(p[1])
  for p in reversed(quiz.hard):
    problems.append(p.content)
    solutions.append(p.answer)
  for p in reversed(quiz.medium):
    problems.append(p.content)
    solutions.append(p.answer)
  for p in reversed(quiz.easy):
    problems.append(p.content)
    solutions.append(p.answer)

  for s, a in zip(reversed(solutions),answers):
    a=a.lower()
    s=s.lower()
    try:
      eq1 = parse_expr(a, transformations=transformations)
      eq2 = parse_expr(s, transformations=transformations)
      if eq1.equals(eq2):
        good += 1
        grades.append(1)
      else:
        grades.append(0)
    except:
      grades.append(0)

  grade=100.0*good/len(problems)
  stringgrade=str(round(grade,1))+"%"
  record = zip(reversed(problems), reversed(solutions), answers, grades)
  #utc = pytz.timezone('UTC')
  #aware_date = utc.localize(datetime.datetime.now())
  #aware_date.tzinfo
  #aware_date.strftime("%a %b %d %H:%M:%S %Y")
  #eastern = pytz.timezone('US/Eastern')
  #eastern_date = aware_date.astimezone(eastern)
  #eastern_date.tzinfo
  #eastern_date.strftime("%a %b %d %H:%M:%S %Y")


  result = Result(parent=quiz.key)
  result.student = Author( identity=self.user.name, email=self.user.email_address)
  result.studentUrl = self.user.key.urlsafe()
  result.floatGrade = grade
  result.stringGrade = stringgrade
  result.record = record
  result.quizName = quiz.name
  result.quizUrl = quiz.key.urlsafe()
  #result.date = eastern_date
  result.courseUrl = courseUrl
  quiz.numberCompleted += 1
  quiz.results.append(result)

  if not self.user.isTeacher:
    result.put()
    result.url = result.key.urlsafe()
    result.put()
    quiz.put()


  print result.url
  self.render_template('quiz.html', {'result': result })


