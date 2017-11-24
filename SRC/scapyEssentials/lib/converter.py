class Converter(object):
    """Class for simple conversions"""
    
    def symString(self, packet, field):
            """Shows the symblic string for a given field

            Where p is UDP(), and you want p.dport symbolically:
                symString(p, 'dport')
            
            Where p is UDP()/DNS(), and you want p[DNS].opcode symbolically:
                symString(p[DNS], 'opcode')
            """
            return packet.get_field(field).i2repr(packet, getattr(packet, field))
