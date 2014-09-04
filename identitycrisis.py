#!/usr/bin/env python
# encoding: utf-8
"""
identitycrisis.py

Created by Sandro Gauci on 2014-04-23.
Copyright (c) 2014 Enable Security ltd. All rights reserved.

Inspired from Chris John Riley's excellent UATester:
<http://blog.c22.cc/toolsscripts/>
"""

from difflib import SequenceMatcher
import threading

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IScanIssue
from javax.swing import JMenuItem
from javax.swing import JMenu
from javax.swing import JFileChooser
from java.util import ArrayList
from java.io import PrintWriter



EXTENSION_NAME = 'Identity Crisis (User-Agent Tester)'
__VERSION__ = 0.2
DEBUG = False

class Similarity:
    """
    Train with strings/buffers to find a norm, then use is_different()
    to see if a particular content is different from the norm
    """
    def __init__(self, initdata, lower=False):
        self.lower = lower
        self.initdata = self.getsection(initdata)
        self.norm = 10.0

    def getsection(self, data):
        if self.lower:
            if len(data) > 1024:
                data = data[-1024:]
            else:
                data = ''
        else:
            data = data[:1024]
        return data

    def train(self, newdata):
        newratio = self.get_ratio(newdata)
        if self.norm > newratio:
            self.set_norm(newratio)

    def get_ratio(self, newdata):
        newdata = self.getsection(newdata)
        s = SequenceMatcher(lambda x: x == " ",
                            self.initdata,
                            newdata)
        return s.ratio()

    def set_norm(self, norm):
        self.norm = norm

    def is_different(self, newdata):
        ratio = self.get_ratio(newdata)
        if ratio < self.norm:
            return True
        return False


class BurpExtender(IBurpExtender, IContextMenuFactory):
    banned_headers = ['expires', 'vtag', 'etag', 'date', 'time', 'set-cookie', 'x-transaction', 'x-cache', 'age']
    useragents = dict()
    useragents['Desktop Web Browsers'] = \
        [
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0)",
            "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
            "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
            "Mozilla/4.0 (compatible;MSIE 5.5; Windows 98)",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)",
            "Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100922 Firefox/4.0.1",
            "Mozilla/5.0 (Windows; U; Windows NT 5.2; rv:1.9.2) Gecko/20100101 Firefox/3.6",
            "Mozilla/5.0 (X11; U; SunOS sun4v; en-US; rv:1.8.1.3) Gecko/20070321 Firefox/2.0.0.3",
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7",
            "Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.27 Safari/525.13",
            "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/533.17.8 (KHTML, like Gecko) Version/5.0.1 Safari/533.17.8",
            "Opera/9.99 (Windows NT 5.1; U; pl) Presto/9.9.9",
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E;',
        ]
    useragents['Mobile Web Browsers'] = \
        [
            'Mozilla/5.0 (Linux; Android 4.4; Nexus 7 Build/KOT24) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.105 Safari/537.36',
            'Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16',
            'Nokia7650/1.0 Symbian-QP/6.1 Nokia/2.1',
        ]
    useragents['Crawlers and bots'] = \
        [
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Googlebot-Image/1.0",
            "Mediapartners-Google",
            "Mozilla/2.0 (compatible; Ask Jeeves)",
            "msnbot-Products/1.0 (+http://search.msn.com/msnbot.htm)",
            "mmcrawler",
            "TrackBack/1.02",
        ]
    useragents['Devices and non-browsers'] = \
        [
            "Windows-Media-Player/9.00.00.4503",
            "Mozilla/5.0 (PLAYSTATION 3; 2.00)",
            "wispr",
            "Wget 1.9cvs-stable",
            "Lynx (textmode)",
            'Mozilla/5.0',
        ]
    useragents['Attack strings'] = \
        [
            "<script>alert('123')</script>",
            "'",
            "' or 22=22'--",
            "%0d%0a",
            "../../../../../../etc/passwd",
            "../../../../../boot.ini",
            "Mozilla/4.75 (Nikto/2.01)",
            "curl/7.7.2 (powerpc-apple-darwin6.0) libcurl 7.7.2 (OpenSSL 0.9.6b)",
            "w3af.sourceforge.net",
            "HTTrack",
            ".nasl",
            "paros",
            "webinspect",
            "brutus",
            "java",
        ]

    def __init__(self, ):
        self.menuitems = dict()
        self.custom_file_text = 'Load custom user-agent strings from file ...'
        self.generate_menu_items()

    def generate_menu_items(self):
        all_tests = 'All tests'
        if all_tests not in self.useragents.keys():
            _tmparray = list()
            for v in self.useragents.values():
                _tmparray.extend(v)
            self.useragents[all_tests] = _tmparray
        if self.custom_file_text not in self.useragents.keys():
            self.useragents[self.custom_file_text] = []
        for k in self.useragents.keys():
            menuitem = JMenuItem(k, actionPerformed=self.menuItemClicked)
            self.menuitems[menuitem] = k


    def registerExtenderCallbacks(self, callbacks):
        self.menuitems = dict()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerContextMenuFactory(self)
        self._contextMenuData = None
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self.generate_menu_items()
        return

    def createMenuItems(self, contextMenuInvocation):
        menuItemList = ArrayList()
        self._contextMenuData = contextMenuInvocation.getSelectedMessages()
        submenu = JMenu(EXTENSION_NAME)
        for menuitem in sorted(self.menuitems):
            submenu.add(menuitem)
        menuItemList.add(submenu)
        return menuItemList

    def menuItemClicked(self, event):
        if self._contextMenuData is None:
            return
        menutext = event.getSource().getText()
        if menutext == self.custom_file_text:
            self.get_custom_headers_file(event)
        useragents = self.useragents[menutext]
        if len(useragents) == 0:
            return
        if DEBUG:
            self.run_test(self._contextMenuData, useragents)
        else:
            t = threading.Thread(target=self.run_test, args=[self._contextMenuData, useragents])
            t.daemon = True
            t.start()

    def train(self, httpService, requestBytes):
        httpRequestResponse = self._callbacks.makeHttpRequest(httpService, requestBytes)
        httpResponseBytes = self._helpers.bytesToString(httpRequestResponse.getResponse())
        bodyOffset = self._helpers.analyzeRequest(httpResponseBytes).getBodyOffset()
        httpResponseBody = self._helpers.bytesToString(httpResponseBytes[bodyOffset:])
        self.similaritytest_headers.train(self.get_clean_headers(httpResponseBytes))
        self.similaritytest_upperbody.train(httpResponseBody)
        self.similaritytest_lowerbody.train(httpResponseBody)

    def initialise(self, baseRequestResponse):
        httpResponseBytes = self._helpers.bytesToString(baseRequestResponse.getResponse())
        bodyOffset = self._helpers.analyzeRequest(httpResponseBytes).getBodyOffset()
        httpResponseBody = self._helpers.bytesToString(httpResponseBytes[bodyOffset:])
        self.similaritytest_headers = Similarity(self.get_clean_headers(httpResponseBytes))
        self.similaritytest_upperbody = Similarity(httpResponseBody)
        self.similaritytest_lowerbody = Similarity(httpResponseBody, lower=True)

    def get_clean_headers_list(self, httpResponseBytes, banned_headers):
        httpResponseInfo = self._helpers.analyzeResponse(httpResponseBytes)
        httpResponseHeaders = httpResponseInfo.getHeaders()
        newHttpResponseHeaders = list()
        for hdr in httpResponseHeaders:
            _tmp = map(lambda x: x.strip().lower(), hdr.split(':', 1))
            if len(_tmp) == 2:
                k, v = _tmp
                if not k in banned_headers:
                    newHttpResponseHeaders.append(hdr)
            else:
                newHttpResponseHeaders.append(hdr)
        return newHttpResponseHeaders

    def get_clean_headers(self, httpResponseBytes, banned_headers=banned_headers):
        newHttpResponseHeaders = self.get_clean_headers_list(httpResponseBytes, banned_headers)
        httpResponseInfo = self._helpers.analyzeResponse(httpResponseBytes)
        bodyOffset = httpResponseInfo.getBodyOffset()
        httpResponseBody = httpResponseBytes[bodyOffset:]
        newhttpResponseBytes = self._helpers.buildHttpMessage(newHttpResponseHeaders, httpResponseBody)[:bodyOffset]
        return newhttpResponseBytes

    def choose_file(self, event):
        chooseFile = JFileChooser()
        chooseFile.showOpenDialog(None)
        chosenFile = chooseFile.getSelectedFile()
        return str(chosenFile)

    def get_custom_headers_file(self, event):
        self.useragents[self.custom_file_text] = list()
        customheadersfn = self.choose_file(event)
        if customheadersfn is None or customheadersfn == 'None':
            return
        with open(customheadersfn,'r') as customheadersf:
            for line in customheadersf:
                self.useragents[self.custom_file_text].append(line.strip())

    def run_test(self, _contextMenuData, useragents):
        for baseRequestResponse in _contextMenuData:
            httpService = baseRequestResponse.getHttpService()
            requestBytes = baseRequestResponse.getRequest()
            targeturl = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
            self._stdout.println('Target request for this URL: ' + targeturl.toString())
            if baseRequestResponse.getResponse() == None:
                self._stdout.println('No response for this request .. issuing a new request')
                baseRequestResponse = self._callbacks.makeHttpRequest(httpService, requestBytes)
            if baseRequestResponse.getResponse() == None:
                self._stdout.println('Did you get a response')
                continue
            # first we do a test to see how stable the responses are
            # make a first request to compare to
            self.initialise(baseRequestResponse)
            # and we check if the response is totally way off from the one previously recorded
            # if it is then we have to issue a new request - might be an expired session
            self.train(httpService, requestBytes)
            if (self.similaritytest_upperbody.norm < 0.6) and \
                    (self.similaritytest_lowerbody.norm < 0.6) and \
                    (self.similaritytest_headers.norm < 0.6):
                self._stdout.println('The previous request appears to grown fungii.. refreshing')
                baseRequestResponse = self._callbacks.makeHttpRequest(httpService, requestBytes)
                self.initialise(baseRequestResponse)
            # run the same request and analyse the responses to get a standard deviation
            # using the train() function which finds the lowest ratio
            self._stdout.println('training ...')
            for _ in range(10):
                self.train(httpService, requestBytes)
            # reduce norm by 0.05 to account for future changes
            for obj in [self.similaritytest_upperbody, self.similaritytest_lowerbody, self.similaritytest_headers]:
                obj.norm -= 0.05
            # now we check what is the lowest ratio number and use that as a normality tester
            if (self.similaritytest_upperbody.norm < 0.6) and (self.similaritytest_lowerbody.norm < 0.6) and (
                self.similaritytest_headers.norm < 0.6):
                self._stdout.println('The site does not appear stable enough for our tests')
                continue
            dotest = list()
            if (self.similaritytest_lowerbody.norm >= 0.6):
                dotest.append('lowerbody')
            if (self.similaritytest_upperbody.norm >= 0.6):
                dotest.append('upperbody')
            if (self.similaritytest_headers.norm >= 0.6):
                dotest.append('headers')
            self._stdout.println("Norm for headers: " + str(self.similaritytest_headers.norm))
            self._stdout.println("Norm for upper body: " + str(self.similaritytest_upperbody.norm))
            self._stdout.println("Norm for lower body: " + str(self.similaritytest_lowerbody.norm))
            requestInfo = self._helpers.analyzeRequest(requestBytes)
            origRequestBody = requestBytes[requestInfo.getBodyOffset():]

            # remove the user-agent header so that we can add our own later
            newRequestHeaders = self.get_clean_headers_list(requestBytes, banned_headers=['user-agent'])

            # get all reported issues for the target URL so that we later check if the issue is a dupe
            scanIssues = self._callbacks.getScanIssues(None)
            for ua in useragents:
                if len(ua) > 25:
                    issueName = "User-Agent dependent response (%s...%s)" % (ua[:30], ua[-12:])
                else:
                    issueName = "User-Agent dependent response (%s)" % (ua,)
                issueDetail = "Web location responds differently when User-Agent header is set to \"%s\"." % ua
                alreadyscanned = False
                for scanIssue in scanIssues:
                    if (scanIssue.getIssueDetail() == issueDetail) and (scanIssue.getUrl() == targeturl):
                        alreadyscanned = True
                        continue
                if alreadyscanned:
                    self._stdout.println("User-agent: %s is already an issue .. skipping" % ua)
                    continue
                # add the new user agent                
                _newRequestHeaders = newRequestHeaders[:]
                _newRequestHeaders.append(u'User-Agent: ' + ua)
                # build and send http request
                httpMessage = self._helpers.buildHttpMessage(_newRequestHeaders, origRequestBody)
                httpRequestResponse = self._callbacks.makeHttpRequest(httpService, httpMessage)
                # get the response
                httpResponseBytes = self._helpers.bytesToString(httpRequestResponse.getResponse())
                # split up the head from the body
                bodyOffset = self._helpers.analyzeRequest(httpResponseBytes).getBodyOffset()
                httpResponseBody = self._helpers.bytesToString(httpResponseBytes[bodyOffset:])
                change_hdr = None
                change_upperbody = None
                change_lowerbody = None
                # only test stable ones
                if 'headers' in dotest:
                    change_hdr = self.similaritytest_headers.is_different(self.get_clean_headers(httpResponseBytes))
                if 'upperbody' in dotest:
                    change_upperbody = self.similaritytest_upperbody.is_different(httpResponseBody)
                if 'lowerbody' in dotest:
                    change_lowerbody = self.similaritytest_lowerbody.is_different(httpResponseBody)
                if change_lowerbody or change_upperbody or change_hdr:
                    self._stdout.println(
                        "%s - headers: %s upperbody: %s lowerbody: %s" \
                        % (ua, change_hdr, change_upperbody, change_lowerbody))
                    httpmsgs = [baseRequestResponse, httpRequestResponse]
                    issue = ScanIssue(httpService,
                                      self._helpers.analyzeRequest(httpRequestResponse).getUrl(),
                                      httpmsgs,
                                      issueName,
                                      issueDetail,
                                      "Information",
                                      "Firm",
                                      None,
                                      None,
                                      None,
                    )
                    self._callbacks.addScanIssue(issue)
                else:
                    self._stdout.println('No changes detected with "%s"' % ua)
        self._stdout.println('Done')


class ScanIssue(IScanIssue):
    """This is our custom IScanIssue class implementation."""

    def __init__(self, httpService, url, httpMessages, issueName, issueDetail, severity, confidence, issueBackground,
                 remediationDetail, remediationBackground):
        self._issueName = issueName
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._issueDetail = issueDetail
        self._severity = severity
        self._confidence = confidence
        self._remediationDetail = remediationDetail
        self._issueBackground = issueBackground
        self._remediationBackground = remediationBackground

    def getConfidence(self):
        return self._confidence

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

    def getIssueBackground(self):
        return self._issueBackground

    def getIssueDetail(self):
        return self._issueDetail

    def getIssueName(self):
        return self._issueName

    def getIssueType(self):
        return 0

    def getRemediationBackground(self):
        return self._remediationBackground

    def getRemediationDetail(self):
        return self._remediationDetail

    def getSeverity(self):
        return self._severity

    def getUrl(self):
        return self._url

    def getHost(self):
        return 'localhost'

    def getPort(self):
        return int(80)