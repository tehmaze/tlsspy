class Buffer(object):
    def __init__(self, data=b''):
        self.data = bytearray(data)

    def __len__(self):
        return len(self.data)

    def add(self, data, size):
        self.data += bytearray(size)
        pos = len(self.data) - 1
        for i in xrange(size):
            self.data[pos] = data & 0xff
            data >>= 8
            pos -= 1

    def add_fixed(self, sequence, size):
        for item in sequence:
            self.add(item, size)

    def add_variable(self, sequence, size, size_size):
        self.add(len(sequence) * size, size_size)
        for item in sequence:
            self.add(item, size)


class Reader(object):
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def __str__(self):
        return str(self.data)

    def get(self, size):
        if self.pos + size > len(self.data):
            raise SyntaxError('Read overflow')

        x = 0
        for i in xrange(size):
            x <<= 8
            x |= self.data[self.pos]
            self.pos += 1
        return x

    def get_fixed(self, size):
        data = self.data[self.pos:self.pos + size]
        self.pos += size
        return data

    def get_variable(self, size_size):
        size = self.get(size_size)
        return self.get_fixed(size)

    def get_fixed_list(self, size, list_size):
        x = [0] * list_size
        for i in xrange(list_size):
            x[i] = self.get(size)
        return x

    def get_variable_list(self, size, size_size):
        list_size = self.get(size_size)
        if list_size % size_size != 0:
            raise SyntaxError('Odd-size frament size requested')
        list_size = list_size / size
        return self.get_fixed_list(size, list_size)

    def size_check_start(self, size_size):
        self.size_check = self.get(size_size)
        self.pos_check = self.pos

    def size_check_set(self, size):
        self.size_check = size
        self.pos_check = self.pos

    def size_check_stop(self):
        if (self.pos - self.pos_check) != self.size_check:
            raise SyntaxError()

    @property
    def at_size_check(self):
        if (self.pos - self.pos_check) < self.size_check:
            return False
        elif (self.pos - self.pos_check) == self.size_check:
            return True
        else:
            raise SyntaxError('Read buffer overflow')
