'''
Created on Jan 30, 2017

@author: Matthew
'''
from selenium import webdriver

from selenium.webdriver.support.ui import WebDriverWait

import unittest



class LoginTest(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Chrome('C:\Users\Matthew\Downloads\chromeDriver.exe')
        self.driver.get("https://math-quizzes-sc.appspot.com/login")
        
    def test_Login(self):
        driver = self.driver
        testUserName = "JohnBanks"
        testPassword = "testing"
        userFieldID  = "username"
        passwordFieldID = "password"
        loginButtonXpath = "login-submit"
        ##homeTestXpath = "//*[@id="wrapper"]/nav/div[2]/div/ul/li[1]/a
        
        emailFieldElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(userFieldID))
        passFieldElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(passwordFieldID))
        loginButtonElement = WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_id(loginButtonXpath))
        
        emailFieldElement.clear()
        emailFieldElement.send_keys(testUserName)
        passFieldElement.clear()
        passFieldElement.send_keys(testPassword)
        loginButtonElement.click()
        ##WebDriverWait(driver, 10).until(lambda driver: driver.find_element_by_xpath(homeTestXpath))
        
    def tearDown(self):
        self.driver.quit()
        
if __name__ == '__main__':
    unittest.main()
        