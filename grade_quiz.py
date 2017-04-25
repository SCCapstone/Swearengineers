#!/usr/bin/env python
from main import *
from sympy import *
from sympy.parsing.sympy_parser import parse_expr
from sympy.parsing.sympy_parser import standard_transformations, \
    implicit_multiplication_application


################################################################################
# Function:  Grade Quiz
#   - Called from the class inQuizzesHandler in main.py
#   - Grades / Records / Shows Results
################################################################################
def grade_quiz(self, user_key, Author, Problem, Quiz, Result):
    transformations = (standard_transformations +
                       (implicit_multiplication_application,))
    posted = self.request.POST.items()
    courseUrl = self.user.selectedCourseKey
    course = ndb.Key(urlsafe=courseUrl).get()
    if self.user.isTeacher:
        quiz = ndb.Key(urlsafe=course.selectedQuizKey).get()
    else:
        qkey = self.request.get('key')
        quiz = ndb.Key(urlsafe=qkey).get()

    good = 0
    problems = []
    solutions = []
    answers = []
    grades = []

    for p in posted:
        if not p[1]:
            answers.append('blank')
        else:
            answers.append(p[1])

    correct_hard = 0
    correct_medium = 0
    correct_easy = 0

    answers_idx = 0

    for p in quiz.easy:
        a = answers[answers_idx]
        answers_idx += 1
        s = p.answer.lower()
        try:
            eq1 = parse_expr(a, transformations=transformations)
            eq2 = parse_expr(s, transformations=transformations)

            if eq1.equals(eq2):
                print 'e %s == %s   TRUE' % (a, s)
                correct_easy += 1
        finally:
            problems.append(p.content)
            solutions.append(p.answer)

    for p in quiz.medium:
        a = answers[answers_idx]
        answers_idx += 1
        s = p.answer.lower()
        try:
            eq1 = parse_expr(a, transformations=transformations)
            eq2 = parse_expr(s, transformations=transformations)

            if eq1.equals(eq2):
                print 'm %s == %s   TRUE' % (a, s)
                correct_medium += 1

        finally:
            problems.append(p.content)
            solutions.append(p.answer)

    for p in quiz.hard:
        a = answers[answers_idx]
        answers_idx += 1
        s = p.answer.lower()
        try:
            eq1 = parse_expr(a, transformations=transformations)
            eq2 = parse_expr(s, transformations=transformations)

            if eq1.equals(eq2):
                print 'h %s == %s   TRUE' % (a, s)
                correct_hard += 1

        finally:
            problems.append(p.content)
            solutions.append(p.answer)


    for s, a in zip(solutions, answers):
        a = a.lower()
        s = s.lower()
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

    print 'correct hard ', correct_hard
    print 'correct med', correct_medium
    print 'correct easy', correct_easy

    correct_hard = min(quiz.required_hard, correct_hard)
    correct_medium = min(quiz.required_medium, correct_medium)
    correct_easy = min(quiz.required_easy, correct_easy)

    print 'req hard', quiz.required_hard
    print 'req med', quiz.required_medium
    print 'req', quiz.required_easy

    try:
        grade = 100.0 * (correct_hard + correct_medium + correct_easy) / (
            quiz.required_hard + quiz.required_medium + quiz.required_easy)
    except:
        grade = 100.0
    stringgrade = str(round(grade, 1)) + "%"
    record = zip(problems, solutions, answers, grades)

    result = Result(parent=quiz.key)
    result.student = Author(
        identity=(self.user.name + ' ' + self.user.last_name),
        email=self.user.email_address
    )
    result.studentUrl = self.user.key.urlsafe()
    result.floatGrade = grade
    result.stringGrade = stringgrade
    result.record = record
    result.quizName = quiz.name
    result.quizUrl = quiz.key.urlsafe()
    result.courseUrl = courseUrl
    quiz.numberCompleted += 1
    quiz.results.append(result)

    if not self.user.isTeacher:
        result.put()
        result.url = result.key.urlsafe()
        result.put()
        quiz.put()

    if self.user.isTeacher:
        self.render_template('quiz.html', {'result': result})

    else:
        self.render_template('quiz.html', {'result': result, 'selectedquiz': quiz})
