import { Controller, Get } from '@nestjs/common';

// Health endpoints. K8s pokes these to know if the pod is alive and ready.
// Skeleton stage: both just say OK. Later /ready will check real deps (DB, Kafka).
@Controller('health')
export class HealthController {
  // Liveness = "am I alive?". If this fails, K8s restarts the pod.
  @Get('live')
  live(): { status: string } {
    return { status: 'ok' };
  }

  // Readiness = "ready for traffic?". If this fails, K8s stops sending requests.
  // For now always ready; no dependencies to check yet.
  @Get('ready')
  ready(): { status: string } {
    return { status: 'ready' };
  }
}
