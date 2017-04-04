#!/usr/bin/env python
from main import *
from sympy import *
from sympy.parsing.sympy_parser import parse_expr

################################################################################
# Function:  Grade Quiz
#   - Called from the class inQuizzesHandler in main.py
#   - Grades / Records / Shows Results
################################################################################
def grade_quiz(self, user_key, Author, Problem, Quiz, Grades):
   quiz_name = self.request.get('selected')
   user = self.user
   pq = Problem.query().filter(Problem.quiz == quiz_name)
   probs = pq.fetch()
   total=0
   good=0
   problems=[]
   answers=[]
   grades=[]
   for p in probs:
     total += 1
     my = self.request.get(str(total))
     answers.append(my)
     problems.append(p.content)
     eq1 = parse_expr(my)
     eq2 = parse_expr(p.answer)
     if eq1.equals(eq2):
        good += 1
        grades.append(1)
     else:
        grades.append(0)
   grade=100.0*good/total
   stringgrade=str(round(grade,1))+"%"
   pag = zip(problems, answers, grades)
   gradeRecord = Grades(parent=user_key(user.email_address))
   gradeRecord.author = Author(
              identity=user.name,
              email=user.email_address)
   gradeRecord.value=grade
   gradeRecord.stringgrade=stringgrade
   gradeRecord.quiz=quiz_name
   gradeRecord.pag= pag
   gradeRecord.put()

   gdate=gradeRecord.date.strftime("%B %d, %Y, %I:%M%P")

   qq = Quiz.query().filter(Quiz.name == quiz_name)
   quiz=qq.fetch()
   for q in quiz:
       q.jgrades.append([user.name,stringgrade, gradeRecord.key.urlsafe(), gdate])
       q.put()

   self.render_template('quiz.html', {'selectdefault': quiz_name, 'grade': gradeRecord})
