global ansTable : table[addr] of set[string]= table();
event http_header(c: connection, is_orig: bool, name: string, value: string)
{		
	if(name == "USER-AGENT")
	{
		if(c$id$orig_h in ansTable)
		{
			if(!(to_lower(value) in ansTable[c$id$orig_h])){
            	add ansTable[c$id$orig_h][to_lower(value)];
            }
		}
		else{
			ansTable[c$id$orig_h]=set(to_lower(value));
		}
	}
}

event zeek_done()
{
	for (Addr, auSet in ansTable)
	{
		if(|auSet|>=3)
		{
			print fmt("%s is a proxy",Addr);
		}
	}
}