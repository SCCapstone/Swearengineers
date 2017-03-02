'''
Created on Jan 30, 2017
Updated February 25, 2017

@author: Matthew
'''
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait

import unittest, time



class LoginTest(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Chrome('C:\Users\Matthew\Downloads\chromeDriver.exe')
        self.driver.get("http://localhost:8080/")
        
    def test_Login(self):
        driver = self.driver
        testUserName = "Guy"
        testPassword = "hollos"
        userFieldID  = "username"
        passwordFieldID = "password"
        loginButtonPath = "login-submit"
        createProblemPath = "//a[@href='/inProblem']"
        testLatex = "x^{xy}"
        testLatexID = "textbox"
        testAnswer = "Some Numbers"
        testAnswerID = "answerbox"
        testKeyword = "Problem 3"
        testKeywordID = "tagbox"
        saveButtonPath = "next"
        viewProblemPath = "//a[@href='/inMyProblems']"
        deleteProblemPath = "deleteButton"
        
        emailFieldElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(userFieldID))
        passFieldElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(passwordFieldID))
        loginButtonElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(loginButtonPath))
        
        emailFieldElement.clear()
        emailFieldElement.send_keys(testUserName)
        passFieldElement.clear()
        passFieldElement.send_keys(testPassword)
        loginButtonElement.click()
        
        createProblemElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_xpath(createProblemPath))

        createProblemElement.click()
        
        latexFieldElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(testLatexID))
        answerFieldElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(testAnswerID))
        keywordFieldElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(testKeywordID))
        
        latexFieldElement.clear()
        latexFieldElement.send_keys(testLatex)
        answerFieldElement.clear()
        answerFieldElement.send_keys(testAnswer)
        keywordFieldElement.clear()
        keywordFieldElement.send_keys(testKeyword)
        
        saveButtonElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(saveButtonPath))
        
        saveButtonElement.click()
        
        viewProblemElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_xpath(viewProblemPath))

        viewProblemElement.click()
        
        deleteProblemElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(deleteProblemPath))
        
        deleteProblemElement.click()
        
        
    def tearDown(self):
        time.sleep(5)
        self.driver.quit()
        
if __name__ == '__main__':
    unittest.main()