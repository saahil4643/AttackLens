import { useEffect, useRef, useCallback } from 'react';

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  alpha: number;
  size: number;
  label: string;
  life: number;
  maxLife: number;
}

const LABELS = [
  '0x4A2F', '10.0.0.1', 'FF:A4:3B', '01101', 'SHA256',
  '443/tcp', 'CVE-', 'AES128', 'RSA', '0xDEAD', '::1',
  'GET /', 'POST', 'JWT', 'SSRF', 'XSS', 'SQLi', 'RCE',
  '172.16', '192.168', '255.255', 'nmap', 'SCAN',
];

interface ParticleBackgroundProps {
  count?: number;
  className?: string;
}

export const ParticleBackground: React.FC<ParticleBackgroundProps> = ({
  count = 28,
  className = '',
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<Particle[]>([]);
  const mouseRef = useRef({ x: 0, y: 0 });
  const animRef = useRef<number>(0);

  const createParticle = useCallback((canvas: HTMLCanvasElement): Particle => {
    const maxLife = 120 + Math.random() * 180;
    return {
      x: Math.random() * canvas.width,
      y: canvas.height + 10,
      vx: (Math.random() - 0.5) * 0.4,
      vy: -(0.3 + Math.random() * 0.5),
      alpha: 0,
      size: 8 + Math.random() * 6,
      label: LABELS[Math.floor(Math.random() * LABELS.length)],
      life: 0,
      maxLife,
    };
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    // Seed initial particles spread across heights
    particlesRef.current = Array.from({ length: count }, () => {
      const p = createParticle(canvas);
      p.y = Math.random() * canvas.height;
      p.life = Math.random() * p.maxLife;
      return p;
    });

    const onMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseRef.current = { x: e.clientX - rect.left, y: e.clientY - rect.top };
    };
    window.addEventListener('mousemove', onMouseMove);

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      particlesRef.current.forEach((p, i) => {
        p.life++;
        const progress = p.life / p.maxLife;
        p.alpha = progress < 0.1 ? progress * 10 : progress > 0.8 ? (1 - progress) * 5 : 1;

        // Subtle mouse repulsion
        const dx = p.x - mouseRef.current.x;
        const dy = p.y - mouseRef.current.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 80) {
          p.vx += (dx / dist) * 0.03;
          p.vy += (dy / dist) * 0.03;
        }

        p.vx *= 0.99;
        p.vy *= 0.99;
        p.x += p.vx;
        p.y += p.vy;

        if (p.life >= p.maxLife) {
          particlesRef.current[i] = createParticle(canvas);
          return;
        }

        ctx.save();
        ctx.globalAlpha = p.alpha * 0.45;
        ctx.font = `${p.size}px 'JetBrains Mono', monospace`;
        ctx.fillStyle = '#ef4444';
        ctx.fillText(p.label, p.x, p.y);
        ctx.restore();
      });

      animRef.current = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', onMouseMove);
    };
  }, [count, createParticle]);

  return (
    <canvas
      ref={canvasRef}
      className={`absolute inset-0 w-full h-full pointer-events-none select-none ${className}`}
      style={{ zIndex: 0 }}
    />
  );
};
