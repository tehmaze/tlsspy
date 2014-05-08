class Buffer(object):
    '''
    Write buffer.
    '''

    def __init__(self, data=b''):
        '''
        :arg data: initial data
        '''
        self.data = bytearray(data)

    def __len__(self):
        return len(self.data)

    def add(self, data, size):
        '''
        Adds data to the buffer.

        :arg data: data to add
        :arg size: size specifier
        '''
        self.data += bytearray(size)
        pos = len(self.data) - 1
        for i in xrange(size):
            self.data[pos] = data & 0xff
            data >>= 8
            pos -= 1

    def add_fixed(self, sequence, size):
        '''
        Adds a sequence of fixed size items.

        :arg sequence: iterable sequence with data points
        :arg size: size specifier
        '''
        for item in sequence:
            self.add(item, size)

    def add_variable(self, sequence, size, size_size):
        '''
        Adds a sequence of variable size items.

        :arg sequence: iterable sequence with data points
        :arg size: size specifier
        :arg size_size: size of the size specifier
        '''
        self.add(len(sequence) * size, size_size)
        for item in sequence:
            self.add(item, size)


class Reader(object):
    '''
    Read buffer/parser.

    :ivar data: buffered data
    :ivar pos: read position pointer
    '''
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def __str__(self):
        return str(self.data)

    def get(self, size):
        '''
        Get ``size`` bytes of data and advance the read position pointer.
        '''
        if self.pos + size > len(self.data):
            raise SyntaxError('Read overflow')

        x = 0
        for i in xrange(size):
            x <<= 8
            x |= self.data[self.pos]
            self.pos += 1
        return x

    def get_fixed(self, size):
        '''
        Get a fixed sequence and advance the read position pointer.
        '''
        data = self.data[self.pos:self.pos + size]
        self.pos += size
        return data

    def get_variable(self, size_size):
        '''
        Get a variable sequence and advance the read position pointer.
        '''
        size = self.get(size_size)
        return self.get_fixed(size)

    def get_fixed_list(self, size, list_size):
        '''
        Get a fixed sequence as list and advance the read position pointer.
        '''
        x = [0] * list_size
        for i in xrange(list_size):
            x[i] = self.get(size)
        return x

    def get_variable_list(self, size, size_size):
        '''
        Get a variable sequence as list and advance the read position pointer.
        '''
        list_size = self.get(size_size)
        if list_size % size_size != 0:
            raise SyntaxError('Odd-size frament size requested')
        list_size = list_size / size
        return self.get_fixed_list(size, list_size)

    def size_check_start(self, size_size):
        '''
        Start a size check for the next size specifier we get from the buffer.

        :arg size_size: size specifier length
        '''
        self.size_check = self.get(size_size)
        self.pos_check = self.pos

    def size_check_set(self, size):
        '''
        Set the size check parameters.
        '''
        self.size_check = size
        self.pos_check = self.pos

    def size_check_stop(self):
        '''
        Check if we have advanced our read pointer to the expected position in
        the buffer.
        '''
        if (self.pos - self.pos_check) != self.size_check:
            raise SyntaxError()

    @property
    def at_size_check(self):
        '''
        Peek if we already hit our size check point.
        '''
        if (self.pos - self.pos_check) < self.size_check:
            return False
        elif (self.pos - self.pos_check) == self.size_check:
            return True
        else:
            raise SyntaxError('Read buffer overflow')
