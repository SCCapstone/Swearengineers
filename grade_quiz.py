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
  course = ndb.Key(urlsafe=self.user.selectedCourseKey).get()
  quiz=ndb.Key(urlsafe=course.selectedQuizKey).get()
  transformations = (standard_transformations +
    (implicit_multiplication_application,))
  good=0
  problems=[]
  solutions=[]
  answers=[]
  grades=[]

  for p in posted:
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

  for s, a in zip(solutions,answers):
    eq1 = parse_expr(a, transformations=transformations)
    eq2 = parse_expr(s, transformations=transformations)
    if eq1.equals(eq2):
      good += 1
      grades.append(1)
    else:
      grades.append(0)

  grade=100.0*good/len(problems)
  stringgrade=str(round(grade,1))+"%"
  record = zip(problems, solutions, answers, grades)

  result = Result(parent=user_key(self.user.email_address))
  result.student = Author( identity=self.user.name, email=self.user.email_address)
  result.studentUrl = self.user.key.urlsafe()
  result.floatGrade = grade
  result.stringGrade = stringgrade
  result.record = record
  result.put()

  quiz.numberCompleted += 1
  quiz.results.append(result)
  quiz.put()


#  self.render_template('quiz.html')
  self.render_template('quiz.html', {'result': result })

