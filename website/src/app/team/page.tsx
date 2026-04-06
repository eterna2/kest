import Image from 'next/image';

interface Member {
  name: string;
  role: string;
  desc: string;
  avatar: string;
  tag: string;
  color: string;
  rainbow?: boolean; // memorial marker
}

const cats: Member[] = [
  {
    name: 'BIBI',
    role: 'Chief Toilet Officer',
    desc: 'A plump tuxedo gentleman who treats the litterbox like a Michelin-starred restroom. Inspects every grain. Curious about everything, suspicious of nothing.',
    avatar: '/team/bibi.png',
    tag: 'LEADERSHIP',
    color: 'rgba(195, 192, 255, 0.08)',
  },
  {
    name: 'DOIDOI',
    role: 'Chief Food Officer',
    desc: 'An absolute unit of a ginger tuxedo. Believes every meeting should be catered. Universally adored — hard to say no to a face that wide. Brother to Bibi.',
    avatar: '/team/doidoi.png',
    tag: 'OPERATIONS',
    color: 'rgba(251, 146, 60, 0.08)',
  },
  {
    name: 'MEIMEI',
    role: 'Head of Security',
    desc: 'Elegant white calico with mismatched ear patches — one black, one brown. Vanishes at the first sign of strangers. Married the CFO; unclear how.',
    avatar: '/team/meimei.png',
    tag: 'OPSEC',
    color: 'rgba(56, 189, 248, 0.08)',
  },
  {
    name: 'LUILUI',
    role: 'Head of Public Relations',
    desc: 'Dark grey tabby with British Shorthair vibes. The eldest, but you\'d never know — still acts like it\'s her first day. Will headbutt any human within range.',
    avatar: '/team/luilui.png',
    tag: 'COMMS',
    color: 'rgba(148, 163, 184, 0.08)',
  },
  {
    name: 'MOMO',
    role: 'FX Specialist (Food Xpert)',
    desc: 'Brown tabby with eyes that could launch a thousand ships. Certified gorgeous. Certified round. Reports directly to the CFO on all snack-related policy.',
    avatar: '/team/momo.png',
    tag: 'SPECIALIST',
    color: 'rgba(180, 130, 80, 0.08)',
  },
  {
    name: 'FATFAT',
    role: 'Intern (Emeritus)',
    desc: 'Tiny grey tabby in an oversized orange hoodie. Once attached, could not be removed without professional assistance. Now velcroed to a star. 🌈',
    avatar: '/team/fatfat.png',
    tag: 'IN MEMORIAM',
    color: 'rgba(250, 204, 21, 0.06)',
    rainbow: true,
  },
  {
    name: 'FEOWMEI',
    role: 'Founding Intern (Emeritus)',
    desc: 'The very first hire — a tiny grey tabby with a red ribbon and a heart ten sizes too big. Started the whole thing. Now running QA from above. 🌈',
    avatar: '/team/feowmei.png',
    tag: 'IN MEMORIAM',
    color: 'rgba(250, 204, 21, 0.06)',
    rainbow: true,
  },
  {
    name: 'HEIBAI',
    role: 'Head of Binary Operations',
    desc: 'Fluffy black-and-white philosopher. Everything was a yes or a no, a zero or a one. No grey areas — ironic, given the fur. 🌈',
    avatar: '/team/heibai.png',
    tag: 'IN MEMORIAM',
    color: 'rgba(250, 204, 21, 0.06)',
    rainbow: true,
  },
  {
    name: 'KEATON',
    role: 'QA Tester',
    desc: 'Small, round, and aerodynamically questionable. Brown tabby who found every bug by literally rolling onto it. Spherical, thorough, legendary. 🌈',
    avatar: '/team/keaton.png',
    tag: 'IN MEMORIAM',
    color: 'rgba(250, 204, 21, 0.06)',
    rainbow: true,
  },
  {
    name: 'GREEDY',
    role: 'Head of Acquisitions',
    desc: 'Big dark grey tabby with a name that was also a mission statement. If it fit in a bowl, it was his. If it didn\'t, he\'d try anyway. 🌈',
    avatar: '/team/greedy.png',
    tag: 'IN MEMORIAM',
    color: 'rgba(250, 204, 21, 0.06)',
    rainbow: true,
  },
  {
    name: 'TONTON',
    role: 'Head of Diplomacy',
    desc: 'Big dark grey tabby. Zero teeth, maximum charisma. Tongue permanently deployed. Resolved every conflict through weaponized bleps. 🌈',
    avatar: '/team/tonton.png',
    tag: 'IN MEMORIAM',
    color: 'rgba(250, 204, 21, 0.06)',
    rainbow: true,
  },
];

const humans: Member[] = [
  {
    name: 'FATDOI',
    role: 'Corporate Slave Driver',
    desc: 'The manager. Delegates all critical decisions to the cats, then takes credit. Cracks the whip so the felines don\'t have to lift a paw.',
    avatar: '/team/fatdoi.png',
    tag: 'MANAGEMENT',
    color: 'rgba(168, 85, 247, 0.06)',
  },
  {
    name: 'ETERNA2',
    role: 'Corporate Slave',
    desc: 'Opens cans. Cleans boxes. Occasionally writes code between feeding schedules. The cats tolerate his presence.',
    avatar: '/team/eterna2.png',
    tag: 'MAINTAINER',
    color: 'rgba(148, 163, 184, 0.06)',
  },
];

const alumni: Member[] = [
  {
    name: 'WHISKY',
    role: 'Travelling Consultant',
    desc: 'Stocky pure white cat. Did a brief stint with the collective before his new purrant whisked him off to see the world. Sends postcards. Probably.',
    avatar: '/team/whisky.png',
    tag: 'ALUMNI',
    color: 'rgba(34, 197, 94, 0.06)',
  },
  {
    name: 'TANGYUAN',
    role: 'Former Kitten-in-Residence',
    desc: 'White cat with black ears. Arrived as the tiniest fluffball. Left as a stocky warlord now ruling a completely different household with an iron paw.',
    avatar: '/team/tangyuan.png',
    tag: 'ALUMNI',
    color: 'rgba(34, 197, 94, 0.06)',
  },
];

function MemberCard({ member, featured = false }: { member: Member; featured?: boolean }) {
  return (
    <div style={{
      gridColumn: featured ? 'span 2' : 'span 1',
      gridRow: featured ? 'span 2' : 'span 1',
      backgroundColor: member.color,
      borderRadius: 'var(--radius-xl)',
      padding: featured ? '2.5rem' : '2rem',
      display: 'flex',
      flexDirection: 'column',
      gap: featured ? '1.5rem' : '1rem',
      position: 'relative',
      overflow: 'hidden',
      transition: 'transform 0.3s ease, box-shadow 0.3s ease',
    }} className="kest-glow team-card">
      {/* Tag */}
      <span style={{
        fontSize: '0.6rem',
        fontWeight: 800,
        letterSpacing: '0.15em',
        color: member.rainbow ? 'rgba(250, 204, 21, 0.8)' : 'var(--primary)',
        textTransform: 'uppercase',
      }}>
        {member.tag}
      </span>

      {/* Avatar */}
      <div style={{
        width: featured ? '100%' : '100%',
        aspectRatio: featured ? '16/10' : '1/1',
        borderRadius: 'var(--radius-lg)',
        overflow: 'hidden',
        position: 'relative',
        backgroundColor: 'rgba(0,0,0,0.15)',
      }}>
        <Image
          src={member.avatar}
          alt={`${member.name} portrait`}
          fill
          style={{ objectFit: 'cover', objectPosition: 'center top' }}
          sizes={featured ? '(max-width: 768px) 100vw, 50vw' : '(max-width: 768px) 100vw, 25vw'}
          {...(featured ? { priority: true } : {})}
        />
        {member.rainbow && (
          <div style={{
            position: 'absolute',
            inset: 0,
            background: 'linear-gradient(135deg, rgba(239,68,68,0.08), rgba(251,146,60,0.08), rgba(250,204,21,0.08), rgba(34,197,94,0.08), rgba(59,130,246,0.08), rgba(168,85,247,0.08))',
            pointerEvents: 'none',
          }} />
        )}
      </div>

      {/* Info */}
      <div>
        <h3 style={{ fontSize: featured ? '2rem' : '1.4rem', margin: 0, fontFamily: 'var(--font-display)' }}>{member.name}</h3>
        <p style={{ fontSize: featured ? '0.85rem' : '0.75rem', opacity: 0.5, margin: '0.25rem 0 0 0' }}>{member.role}</p>
      </div>

      <p style={{ fontSize: featured ? '1rem' : '0.85rem', lineHeight: 1.6, opacity: 0.7, margin: 0 }}>{member.desc}</p>
    </div>
  );
}

export default function TeamPage() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '5rem' }}>
      {/* Header */}
      <section>
        <span style={{ fontSize: '0.75rem', fontWeight: 800, letterSpacing: '0.1em', color: 'var(--primary)', textTransform: 'uppercase' }}>
          The Collective
        </span>
        <h1 style={{ fontSize: '3.5rem', marginTop: '0.5rem', fontFamily: 'var(--font-display)' }}>
          Orchestrators of the <span className="gradient-text">Lineage</span>
        </h1>
        <p style={{ fontSize: '1.1rem', color: 'var(--on-surface-variant)', maxWidth: '600px', lineHeight: 1.6 }}>
          13 cats. 2 humans. One mission: cryptographic trust for every hop.
        </p>
      </section>

      {/* Cat Grid — Leadership (BIBI featured) */}
      <section>
        <h2 style={{ fontSize: '0.7rem', fontWeight: 800, letterSpacing: '0.15em', color: 'var(--primary)', textTransform: 'uppercase', marginBottom: '2rem' }}>
          Feline Division
        </h2>
        <div className="team-grid" style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '1.5rem',
        }}>
          <MemberCard member={cats[0]} featured />
          {cats.slice(1).map((member) => (
            <MemberCard key={member.name} member={member} />
          ))}
        </div>
      </section>

      {/* Human Grid */}
      <section>
        <h2 style={{ fontSize: '0.7rem', fontWeight: 800, letterSpacing: '0.15em', color: 'var(--primary)', textTransform: 'uppercase', marginBottom: '2rem' }}>
          Human Division
        </h2>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: '1.5rem',
          maxWidth: '600px',
        }}>
          {humans.map((member) => (
            <MemberCard key={member.name} member={member} />
          ))}
        </div>
      </section>

      {/* Alumni */}
      <section>
        <h2 style={{ fontSize: '0.7rem', fontWeight: 800, letterSpacing: '0.15em', color: 'rgba(34, 197, 94, 0.8)', textTransform: 'uppercase', marginBottom: '2rem' }}>
          Alumni Network
        </h2>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: '1.5rem',
          maxWidth: '600px',
        }}>
          {alumni.map((member) => (
            <MemberCard key={member.name} member={member} />
          ))}
        </div>
      </section>
    </div>
  );
}
