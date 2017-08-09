import click
from lxml import etree

@click.command()
@click.option('--config-folder', default='/etc/clickhouse-server', help='Folder where clickhouse config files are located.')
#@click.option('--name', prompt='Your name',help='The person to greet.')
def parse_options(config_folder):
    """Simple program that greets NAME for a total of COUNT times."""
#    for x in range(count):
#        click.echo('Hello %s!' % name)
    print(config_folder)
    return {
        'config-folder': config_folder
    }

def main(options):

    new_entry = etree.fromstring('''
<book category="web" cover="paperback">
    <title lang="en">Learning XML 2</title>
    <author>Erik Ray</author>
    <year>2006</year>
    <price>49.95</price>
</book>
'''
                                 )

    tree = etree.parse('books.xml')
    root = tree.getroot()

    print(etree.tostring(root, pretty_print=True).decode("utf-8"))
    root.append(new_entry)
    print(etree.tostring(root, pretty_print=True).decode("utf-8"))

    f = open('books-mod.xml', 'w')
    f.write(etree.tostring(root, pretty_print=True).decode("utf-8"))
    f.close()


if __name__ == '__main__':
    options = parse_options()
    main(options)




from StringIO import StringIO
from lxml import etree
from lxml.etree import Element

data = """<xml>
   <items>
      <pie>cherry</pie>
      <pie>apple</pie>
      <pie>chocolate</pie>
  </items>
</xml>"""

stream = StringIO(data)
context = etree.iterparse(stream, events=("start", ))

for action, elem in context:
    if elem.tag == 'items':
        items = elem
        index = 1
    elif elem.tag == 'pie':
        item = Element('item', {'id': str(index)})
        items.replace(elem, item)
        item.append(elem)
        index += 1

print etree.tostring(context.root)

prints:

<xml>
   <items>
      <item id="1"><pie>cherry</pie></item>
      <item id="2"><pie>apple</pie></item>
      <item id="3"><pie>chocolate</pie></item>
   </items>
</xml>


<example>
    <login>
        <id>1</id>
        <username>kites</username>
        <password>kites</password>
    </login>
</example>
example = etree.Element("example")
login = etree.SubElement(example, "login")
password = etree.SubElement(login,"password")
password.text = "newPassword"
