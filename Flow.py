class Flow():

    def __init__(self, flow_type, flow_duration, flow_size, arrival_time, TCP_state):
        '''

        '''
        self.type = flow_type
        self.duration = flow_duration
        self.size = flow_size
        self.arr_time = arrival_time
        self.state = TCP_state
