# Class Stack is used only for Stack management i.e. for undo and redo operations
class Stack:

    def __init__(self, text):
        self.stack = []
        self.stack.append(text)

    def add(self, dataval):
        if dataval not in self.stack:
            self.stack.append(dataval)
            return True
        else:
            return False

    def remove(self):
        if len(self.stack) <= 1:
            return "No element in the Stack"
        else:
            return self.stack.pop()

    def peek(self):
        if len(self.stack) == 1:
            return self.stack[0]
        else:
            return self.stack[-1]

    def print_all(self):
        length = len(self.stack) - 1
        while self.stack:
            print(self.stack[length])
            length -= 1

    def size(self):
        return len(self.stack)

    def clear_stack(self):
        return self.stack.clear()

    def ele(self, index):
        return self.stack[index]
