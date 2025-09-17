# BTteaLFI
# Copyright (C) 2024-2025 BTtea
#
# This file is licensed under GPLv2. See LICENSE.txt for details.

class BodyData:
    def __init__(self, body):
        self.body = body if body else ''
        self.DataType = 'query'
        self.post_param = ''

    def __str__(self):
        return self.body

    def __repr__(self):
        return self.__str__()