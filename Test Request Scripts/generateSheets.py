from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# Read credentials from file
students = []
with open("Backend\Test Request Scripts\serverCredentials.txt", "r") as f:
    for line in f:
        username, password = line.strip().split()
        students.append({"username": username, "password": password})

# PDF setup
c = canvas.Canvas("student_logins.pdf", pagesize=A4)
width, height = A4

# Block/card layout
card_width = 250
card_height = 100
gap_x = 20
gap_y = 20
x_start = 50
y_start = height - 50

x = x_start
y = y_start

for i, student in enumerate(students):
    # Draw block rectangle
    c.rect(x, y - card_height, card_width, card_height)
    
    # Add student credentials inside the block
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x + 10, y - 30, f"Username: {student['username']}")
    c.drawString(x + 10, y - 50, f"Password: {student['password']}")
    
    # Move to next block
    x += card_width + gap_x
    if x + card_width > width:  # move to next row
        x = x_start
        y -= card_height + gap_y
        if y - card_height < 0:  # new page if necessary
            c.showPage()
            x = x_start
            y = y_start

c.save()
print("PDF generated: student_logins.pdf")
