% Open matching DHCP log and pcap files, read MAC adresses from DHCP log and save anonymised DHCP log
% and pcap files.


PathName = 'I:\mobx\broadcast_wifi\Trials\UoH\capture\';

FilterSpec = '*.txt';
[FileName_in_dhcp,PathName,FilterIndex] = uigetfile(FilterSpec);

fid_dhcp = fopen([PathName,FileName_in_dhcp]);

%get list of MAC addresses
mac_idx = 1;
mac_str=string([]);


while ~feof(fid_dhcp)
    instr = fgets(fid_dhcp);
        if ~isempty(findstr(instr(32:end),':')) 
             p = findstr(instr(32:end),':');
             if length(p)==5
                 mac_str(mac_idx,:) = instr(p(1)+29:p(end)+33);
                mac_idx=mac_idx+1;
             end
        end

end

%Unique values of mac address
mac_str=unique(mac_str);

%go back to start of file
frewind(fid_dhcp);

idx = strfind(FileName_in_dhcp,'.');
FileName_out_dhcp = [FileName_in_dhcp(1:idx(end)-1),'_anon',FileName_in_dhcp(idx(end):end)];
mac_anon = string([]);
% create anonymous array
for a=1:length(mac_str)
        anon = dec2hex(a);
        tmp=char(mac_str(a));
        tmp(10:end)='00:00:00';
        colons = 0;
        for b=1:length(anon)
            if isempty(strfind(tmp(end-b+1-colons),':'))
                tmp(end-b-colons+1)=anon(end-b+1);
                
            else % skip the :
                colons = colons + 1;
                tmp(end-b-colons+1)=anon(end-b+1);
            end
                
        end 
        mac_anon(a) = tmp;       
end

%go back to start of file
frewind(fid_dhcp);

fid_dhcp_out=fopen([PathName,FileName_out_dhcp],'w');

while ~feof(fid_dhcp)
        instr = fgets(fid_dhcp);
    
    % check to see if mac address in line and replace with number
    mac_found= false;
    a = 1;
    while ~mac_found && a < length(mac_str)
        tmp = char(mac_str(a));

        
        
        if ~isempty(strfind(instr,tmp))
            outstr = char(strrep(instr,tmp,char(mac_anon(a))));
                
            % find device name and replace
            if findstr(instr(strfind(instr,tmp):end),'(')
                idx1 = strfind(outstr,'(');
                idx2 = strfind(outstr,')');
                if ~isempty(idx1)
                    outstr = strrep(outstr,outstr(idx1(end):idx2(end)),['(Device_',num2str(a),')']);
                end
                
            end
            mac_found = true;
        else
            outstr = instr;
        end
        a = a + 1;
    end
 
    fprintf(fid_dhcp_out,'%s',outstr);
end

fclose(fid_dhcp_out);





% Open pcap file
FilterSpec = '*.pcap';
[FileName_in_pcap,PathName,FilterIndex] = uigetfile(FilterSpec);

idx = strfind(FileName_in_pcap,'.');

FileName_out_pcap=[FileName_in_pcap(1:idx(end)-1),'_anon',FileName_in_pcap(idx(end):end)];

fid_in=fopen([PathName,FileName_in_pcap]);

fid_out=fopen([PathName,FileName_out_pcap],'w');

disp('reading file');
my_data=fread(fid_in);

%create arrays of raw mac addresses
mac_8 = zeros(6,length(mac_str));
mac_8_anon = zeros(6,length(mac_str));
for  a = 1:length(mac_str)
     tmp = mac_str(a);
     tmp = char(strrep(tmp,':',''));
     mac_8(:,a)=([hex2dec(tmp(1:2));hex2dec(tmp(3:4));hex2dec(tmp(5:6));hex2dec(tmp(7:8));hex2dec(tmp(9:10));hex2dec(tmp(11:12))]).';
     
     tmp = mac_anon(a);
     tmp = char(strrep(tmp,':',''));
     mac_8_anon(:,a)=([hex2dec(tmp(1:2));hex2dec(tmp(3:4));hex2dec(tmp(5:6));hex2dec(tmp(7:8));hex2dec(tmp(9:10));hex2dec(tmp(11:12))]).';

end

% flpi arrays
mac_8=mac_8.';
mac_8_anon=mac_8_anon.';

tmp5 = char(my_data.');
%replace data in array
for a=1:length(mac_8)
    tmp5=strrep(tmp5,char(mac_8(a,:)),char(mac_8_anon(a,:)));
end


disp('writing file');
fwrite(fid_out,tmp5);
fclose(fid_in);
fclose(fid_out);
