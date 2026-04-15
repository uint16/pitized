import dgram from 'dgram';

export class UdpService {
  async discover(): Promise<{ ip: string }[]> {
    return new Promise(resolve => {
      const found: { ip: string }[] = [];
      const client = dgram.createSocket('udp4');
      
      client.on('message', (_, r) => { 
        if (!found.find(f => f.ip === r.address)) {
          found.push({ ip: r.address }); 
        }
      });
      
      client.on('error', () => { 
        client.close(); 
        resolve(found); 
      });
      
      client.bind(() => { 
        client.setBroadcast(true); 
        const c = Buffer.from('81090002ff','hex'); 
        [1259, 5678].forEach(p => client.send(c, p, '255.255.255.255')); 
      });
      
      setTimeout(() => { 
        client.close(); 
        resolve(found); 
      }, 3000);
    });
  }

  async visca(ip: string, hexCmd: string, port: number = 1259): Promise<{ success: boolean; response?: string; error?: string }> {
    return new Promise(resolve => {
      try {
        const client = dgram.createSocket('udp4');
        const buf = Buffer.from(hexCmd, 'hex');
        const t = setTimeout(() => { 
          client.close(); 
          resolve({ success: false, error: 'timeout' }); 
        }, 2000);
        
        client.on('message', msg => { 
          clearTimeout(t); 
          client.close(); 
          resolve({ success: true, response: msg.toString('hex') }); 
        });
        
        client.send(buf, port, ip, err => { 
          if (err) { 
            clearTimeout(t); 
            client.close(); 
            resolve({ success: false, error: err.message }); 
          } 
        });
      } catch (err: any) { 
        resolve({ success: false, error: err.message }); 
      }
    });
  }
}

export const udpService = new UdpService();
