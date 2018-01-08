#!/usr/bin/env python
# -*- coding: utf-8 -*-


from .chmanager import CHManager


class Main(object):
    def start(self):
        # print("RUN")
        manager = CHManager();
        manager.main()



# from StringIO import StringIO
# from lxml import etree
# from lxml.etree import Element
#
# data = """<xml>
#    <items>
#       <pie>cherry</pie>
#       <pie>apple</pie>
#       <pie>chocolate</pie>
#   </items>
# </xml>"""

# stream = StringIO(data)
# context = etree.iterparse(stream, events=("start", ))
#
# for action, elem in context:
#     if elem.tag == 'items':
#         items = elem
#         index = 1
#     elif elem.tag == 'pie':
#         item = Element('item', {'id': str(index)})
#         items.replace(elem, item)
#         item.append(elem)
#         index += 1
#
# print etree.tostring(context.root)
#
# prints:
#
# <xml>
#    <items>
#       <item id="1"><pie>cherry</pie></item>
#       <item id="2"><pie>apple</pie></item>
#       <item id="3"><pie>chocolate</pie></item>
#    </items>
# </xml>
#
#
# <example>
#     <login>
#         <id>1</id>
#         <username>kites</username>
#         <password>kites</password>
#     </login>
# </example>
# example = etree.Element("example")
# login = etree.SubElement(example, "login")
# password = etree.SubElement(login,"password")
# password.text = "newPassword"

if __name__ == '__main__':
    main = Main()
    main.start()
