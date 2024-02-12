import re
import os
import json
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.io import PrintWriter
from threading import Thread

class BurpExtender(IBurpExtender, IContextMenuFactory, ActionListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self._callbacks.setExtensionName("Send and Process Request in Background")
        self._callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        self.context = None
        if invocation.getInvocationContext() == invocation.CONTEXT_PROXY_HISTORY:
            self.context = invocation
            menu_list = []
            menu_item = JMenuItem("Extract Webpack")
            menu_item.addActionListener(self)
            menu_list.append(menu_item)
            return menu_list
        return None

    def actionPerformed(self, event):
        thread = Thread(target=self.handleRequest)
        thread.start()

    def handleRequest(self):
        try:
            # request_info = self.context.getSelectedMessages()[0]
            selected_messages = self.context.getSelectedMessages()
            for request_info in selected_messages:
                http_service = request_info.getHttpService()
                request_bytes = request_info.getRequest()

                response_info = self._callbacks.makeHttpRequest(http_service, request_bytes)

                response_bytes = response_info.getResponse()
                if response_bytes:
                    self.processResponse(response_bytes)
        except Exception as e:
            self.stdout.println("Exception occurred: " + str(e))

    def processResponse(self, response_bytes):
        analyzed_response = self._helpers.analyzeResponse(response_bytes)
        headers = analyzed_response.getHeaders()
        body_offset = analyzed_response.getBodyOffset()
        body_bytes = response_bytes[body_offset:]
        body_str = self._helpers.bytesToString(body_bytes)

        request_info = self.context.getSelectedMessages()[0]
        request_bytes = request_info.getRequest()
        request_str = self._helpers.bytesToString(request_bytes)
        folder_name = self.createSafeFolderName(request_str)

        base_path = os.path.expanduser('~/Documents/Hacking/Bounty Programs/Webpack_Extract')
        full_path = os.path.join(base_path, folder_name)
        try:
            if not os.path.exists(full_path):
                os.makedirs(full_path)
        except Exception as e:
            self.stdout.println("Error saving response body: " + str(e))

        try:
            json_data = json.loads(body_str)
            if 'sources' and 'sourcesContent' in json_data:
                sources = json_data['sources']
                sourcesContent = json_data['sourcesContent']
                for source, sourceContent in zip(sources, sourcesContent):

                    ## change this

                    # string_to_remove = "webpack://external-site/.." if "/../" in source else "webpack://external-site/."
                    string_to_remove = "/../../"
                    
                    
                    original = source
                    newstring = full_path + original.replace(string_to_remove, "")
                    decoded_content = sourceContent.encode('utf-8')

                    path_parts = os.path.split(newstring)
                    directory_path = path_parts[0]
                    file_name = path_parts[1]

                    if not os.path.exists(directory_path):
                        os.makedirs(directory_path)

                    with open(newstring, 'w') as file:
                        file.write(decoded_content)
            else:
                print("No 'sources' or 'sourcesContent' key found in JSON data")
        except ValueError as e:
            print("Error parsing JSON from response body:", e)

    def createSafeFolderName(self, request_str):
        match = re.search(r'Host: ([^\r\n]+)', request_str)
        if match:
            hostname = match.group(1)
            safe_folder_name = re.sub(r'[\\/*?:"<>|]', '_', hostname)
            return safe_folder_name
        else:
            return "default_folder"