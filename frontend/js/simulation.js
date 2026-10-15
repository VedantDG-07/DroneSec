/**
 * DroneSec Simulation World - Three.js WebGL Rendering Engine
 *
 * Implements the mathematical coordinate translation from backend truth:
 *   ThreePosition = (x, y, -z)
 *   ThreeRotationY = -(heading * Math.PI / 180)
 *
 * Procedural low-poly environment:
 * - Island terrain with runway & ocean grid
 * - Helipad with landing rings and "H" marker at (0, 0, 0)
 * - Control tower with aviation warning beacon
 * - Hangar buildings and communication radar
 * - Geofence bounding volume (200m x 50m x 200m)
 * - Procedural Quadcopter Drone with rotating propellers & navigation LEDs
 * - Dynamic flight trail (breadcrumb path)
 */

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/OrbitControls.js';

export class SimulationWorld {
  constructor(canvasElement) {
    this.canvas = canvasElement;
    this.scene = null;
    this.camera = null;
    this.renderer = null;
    this.controls = null;

    // Drone 3D entity & parts
    this.droneGroup = null;
    this.rotors = [];
    this.bellyBeaconLight = null;
    this.droneShadow = null;
    this.flightTrail = null;
    this.trailPoints = [];
    this.maxTrailPoints = 300;

    // Target state from backend (interpolated)
    this.targetState = {
      x: 0,
      y: 0,
      z: 0,
      heading: 0,
      speed: 0,
      flightState: 'DISARMED',
      armed: false,
    };

    // Camera modes: 'ORBIT', 'CHASE', 'TOPDOWN', 'TOWER'
    this.cameraMode = 'ORBIT';
    this.towerPosition = new THREE.Vector3(25, 20, 25);

    // Animation & clock
    this.clock = new THREE.Clock();
    this.animId = null;

    this.init();
  }

  init() {
    // 1. Scene setup
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(0x06090f);
    this.scene.fog = new THREE.FogExp2(0x06090f, 0.0035);

    // 2. Camera setup
    const aspect = this.canvas.clientWidth / this.canvas.clientHeight;
    this.camera = new THREE.PerspectiveCamera(50, aspect, 0.1, 1000);
    this.camera.position.set(18, 14, 24);

    // 3. Renderer setup
    this.renderer = new THREE.WebGLRenderer({
      canvas: this.canvas,
      antialias: true,
      powerPreference: 'high-performance',
    });
    this.renderer.setSize(this.canvas.clientWidth, this.canvas.clientHeight);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.shadowMap.enabled = true;
    this.renderer.shadowMap.type = THREE.PCFSoftShadowMap;

    // 4. OrbitControls
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.05;
    this.controls.maxPolarAngle = Math.PI / 2 - 0.02; // Don't clip below ground
    this.controls.minDistance = 3;
    this.controls.maxDistance = 180;
    this.controls.target.set(0, 2, 0);

    // 5. Lighting
    this.setupLighting();

    // 6. Environment & Terrain
    this.buildEnvironment();

    // 7. Geofence Cage
    this.buildGeofenceCage();

    // 8. Procedural Drone Model
    this.buildDroneModel();

    // 9. Flight Path Trail
    this.buildFlightTrail();

    // 10. Handle window resizing
    window.addEventListener('resize', () => this.onWindowResize());

    // 11. Start animation loop
    this.animate();
  }

  setupLighting() {
    // Soft ambient sky light
    const hemiLight = new THREE.HemisphereLight(0x38bdf8, 0x0f172a, 0.7);
    this.scene.add(hemiLight);

    // Directional sunlight with shadows
    const sunLight = new THREE.DirectionalLight(0xfffbeb, 1.2);
    sunLight.position.set(60, 90, 40);
    sunLight.castShadow = true;
    sunLight.shadow.mapSize.width = 2048;
    sunLight.shadow.mapSize.height = 2048;
    sunLight.shadow.camera.near = 10;
    sunLight.shadow.camera.far = 250;
    const d = 110;
    sunLight.shadow.camera.left = -d;
    sunLight.shadow.camera.right = d;
    sunLight.shadow.camera.top = d;
    sunLight.shadow.camera.bottom = -d;
    sunLight.shadow.bias = -0.0005;
    this.scene.add(sunLight);

    // Subtle blue fill light
    const fillLight = new THREE.DirectionalLight(0x00d2ff, 0.4);
    fillLight.position.set(-50, 30, -50);
    this.scene.add(fillLight);
  }

  buildEnvironment() {
    // Ocean Plane (Deep navy water with subtle tactical grid)
    const oceanGeo = new THREE.PlaneGeometry(600, 600, 60, 60);
    const oceanMat = new THREE.MeshStandardMaterial({
      color: 0x050c18,
      roughness: 0.2,
      metalness: 0.8,
    });
    const ocean = new THREE.Mesh(oceanGeo, oceanMat);
    ocean.rotation.x = -Math.PI / 2;
    ocean.position.y = -0.3;
    ocean.receiveShadow = true;
    this.scene.add(ocean);

    // Tactical Island Terrain
    const islandGeo = new THREE.CylinderGeometry(85, 95, 0.6, 32);
    const islandMat = new THREE.MeshStandardMaterial({
      color: 0x0f172a,
      roughness: 0.85,
      metalness: 0.1,
    });
    const island = new THREE.Mesh(islandGeo, islandMat);
    island.position.y = -0.15;
    island.receiveShadow = true;
    this.scene.add(island);

    // Runway / Tarmac Strip
    const runwayGeo = new THREE.PlaneGeometry(24, 120);
    const runwayMat = new THREE.MeshStandardMaterial({
      color: 0x161f30,
      roughness: 0.9,
    });
    const runway = new THREE.Mesh(runwayGeo, runwayMat);
    runway.rotation.x = -Math.PI / 2;
    runway.position.set(0, 0.01, 0);
    runway.receiveShadow = true;
    this.scene.add(runway);

    // Coordinate Grid on Runway
    const gridHelper = new THREE.GridHelper(100, 20, 0x00d2ff, 0x1e293b);
    gridHelper.position.y = 0.02;
    gridHelper.material.opacity = 0.3;
    gridHelper.material.transparent = true;
    this.scene.add(gridHelper);

    // 10m x 10m Helipad at Origin (0, 0, 0)
    this.buildHelipad();

    // Airfield Structures (Tower, Hangars, Radar)
    this.buildStructures();
  }

  buildHelipad() {
    const helipadGroup = new THREE.Group();
    helipadGroup.position.set(0, 0.03, 0);

    // Helipad base square (10m x 10m)
    const padGeo = new THREE.PlaneGeometry(10, 10);
    const padMat = new THREE.MeshStandardMaterial({
      color: 0x1e293b,
      roughness: 0.6,
    });
    const padMesh = new THREE.Mesh(padGeo, padMat);
    padMesh.rotation.x = -Math.PI / 2;
    padMesh.receiveShadow = true;
    helipadGroup.add(padMesh);

    // Outer Yellow Target Ring (Radius 4m)
    const ringGeo = new THREE.RingGeometry(3.6, 4.0, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: 0xffb800,
      side: THREE.DoubleSide,
    });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    ringMesh.rotation.x = -Math.PI / 2;
    ringMesh.position.y = 0.01;
    helipadGroup.add(ringMesh);

    // Center "H" Marker (Constructed from 3 planes)
    const hMat = new THREE.MeshBasicMaterial({ color: 0xffffff, side: THREE.DoubleSide });
    
    // Left vertical bar
    const barLeft = new THREE.Mesh(new THREE.PlaneGeometry(0.5, 3.2), hMat);
    barLeft.rotation.x = -Math.PI / 2;
    barLeft.position.set(-1.1, 0.015, 0);
    helipadGroup.add(barLeft);

    // Right vertical bar
    const barRight = new THREE.Mesh(new THREE.PlaneGeometry(0.5, 3.2), hMat);
    barRight.rotation.x = -Math.PI / 2;
    barRight.position.set(1.1, 0.015, 0);
    helipadGroup.add(barRight);

    // Horizontal cross bar
    const barCross = new THREE.Mesh(new THREE.PlaneGeometry(1.7, 0.5), hMat);
    barCross.rotation.x = -Math.PI / 2;
    barCross.position.set(0, 0.015, 0);
    helipadGroup.add(barCross);

    // 4 Corner Perimeter Boundary Lights
    const cornerOffsets = [
      [-4.6, -4.6], [4.6, -4.6], [-4.6, 4.6], [4.6, 4.6]
    ];
    cornerOffsets.forEach(([cx, cz]) => {
      const lightGeo = new THREE.CylinderGeometry(0.12, 0.15, 0.25, 8);
      const lightMat = new THREE.MeshStandardMaterial({
        color: 0x00ff9d,
        emissive: 0x00ff9d,
        emissiveIntensity: 0.8,
      });
      const lightMesh = new THREE.Mesh(lightGeo, lightMat);
      lightMesh.position.set(cx, 0.12, cz);
      helipadGroup.add(lightMesh);
    });

    this.scene.add(helipadGroup);
  }

  buildStructures() {
    // 1. Control Tower at (25, 0, 25)
    const towerGroup = new THREE.Group();
    towerGroup.position.set(25, 0, 25);

    // Main tower column (Octagonal column, height 18m)
    const towerBaseGeo = new THREE.CylinderGeometry(2.5, 3.2, 18, 8);
    const towerBaseMat = new THREE.MeshStandardMaterial({
      color: 0x334155,
      roughness: 0.7,
    });
    const towerBase = new THREE.Mesh(towerBaseGeo, towerBaseMat);
    towerBase.position.y = 9;
    towerBase.castShadow = true;
    towerBase.receiveShadow = true;
    towerGroup.add(towerBase);

    // Observation Cab (Glass dome at height 18m)
    const cabGeo = new THREE.CylinderGeometry(4.2, 3.0, 3.5, 12);
    const cabMat = new THREE.MeshStandardMaterial({
      color: 0x00d2ff,
      roughness: 0.1,
      metalness: 0.9,
      transparent: true,
      opacity: 0.6,
    });
    const cab = new THREE.Mesh(cabGeo, cabMat);
    cab.position.y = 19;
    towerGroup.add(cab);

    // Tower Roof
    const roofGeo = new THREE.ConeGeometry(4.4, 1.5, 12);
    const roofMat = new THREE.MeshStandardMaterial({ color: 0x1e293b });
    const roof = new THREE.Mesh(roofGeo, roofMat);
    roof.position.y = 21.2;
    towerGroup.add(roof);

    // Aviation Red Warning Beacon on Tower Roof
    const beaconGeo = new THREE.SphereGeometry(0.35, 16, 16);
    const beaconMat = new THREE.MeshStandardMaterial({
      color: 0xff0033,
      emissive: 0xff0033,
      emissiveIntensity: 1.0,
    });
    this.towerBeacon = new THREE.Mesh(beaconGeo, beaconMat);
    this.towerBeacon.position.y = 22.4;
    towerGroup.add(this.towerBeacon);

    this.scene.add(towerGroup);

    // 2. Airfield Hangar at (-30, 0, 10)
    const hangarGeo = new THREE.CylinderGeometry(10, 10, 24, 16, 1, false, 0, Math.PI);
    const hangarMat = new THREE.MeshStandardMaterial({
      color: 0x1e293b,
      roughness: 0.6,
    });
    const hangar = new THREE.Mesh(hangarGeo, hangarMat);
    hangar.rotation.z = Math.PI / 2;
    hangar.rotation.y = Math.PI / 4;
    hangar.position.set(-28, 0, 10);
    hangar.castShadow = true;
    hangar.receiveShadow = true;
    this.scene.add(hangar);

    // 3. Radar Antenna Dish at (-20, 0, -25)
    const radarBase = new THREE.Mesh(
      new THREE.CylinderGeometry(0.8, 1.2, 5, 8),
      new THREE.MeshStandardMaterial({ color: 0x475569 })
    );
    radarBase.position.set(-20, 2.5, -25);
    radarBase.castShadow = true;
    this.scene.add(radarBase);

    const dishGeo = new THREE.SphereGeometry(2.5, 16, 16, 0, Math.PI * 2, 0, Math.PI * 0.4);
    const dishMat = new THREE.MeshStandardMaterial({ color: 0x94a3b8, side: THREE.DoubleSide });
    this.radarDish = new THREE.Mesh(dishGeo, dishMat);
    this.radarDish.position.set(-20, 6, -25);
    this.radarDish.rotation.x = Math.PI / 4;
    this.radarDish.castShadow = true;
    this.scene.add(this.radarDish);
  }

  buildGeofenceCage() {
    // Geofence cage: 200m (X) x 50m (Y) x 200m (Z)
    // Centered at (0, 25, 0)
    const boxGeo = new THREE.BoxGeometry(200, 50, 200);
    const edges = new THREE.EdgesGeometry(boxGeo);
    const lineMat = new THREE.LineBasicMaterial({
      color: 0x00d2ff,
      transparent: true,
      opacity: 0.35,
    });
    const wireframe = new THREE.LineSegments(edges, lineMat);
    wireframe.position.set(0, 25, 0);
    this.scene.add(wireframe);

    // Semi-transparent boundary ceiling at Y = 50m
    const ceilingGeo = new THREE.PlaneGeometry(200, 200);
    const ceilingMat = new THREE.MeshBasicMaterial({
      color: 0x00d2ff,
      transparent: true,
      opacity: 0.04,
      side: THREE.DoubleSide,
    });
    const ceiling = new THREE.Mesh(ceilingGeo, ceilingMat);
    ceiling.rotation.x = -Math.PI / 2;
    ceiling.position.set(0, 50, 0);
    this.scene.add(ceiling);
  }

  buildDroneModel() {
    this.droneGroup = new THREE.Group();
    this.droneGroup.position.set(0, 0, 0);

    // Central Fuselage / Carbon Fiber Body
    const bodyGeo = new THREE.BoxGeometry(0.9, 0.28, 1.2);
    const bodyMat = new THREE.MeshStandardMaterial({
      color: 0x0f172a,
      roughness: 0.3,
      metalness: 0.8,
    });
    const body = new THREE.Mesh(bodyGeo, bodyMat);
    body.position.y = 0.25;
    body.castShadow = true;
    this.droneGroup.add(body);

    // Fuselage Top Shell (Aerodynamic canopy)
    const canopyGeo = new THREE.SphereGeometry(0.42, 16, 12);
    canopyGeo.scale(1.0, 0.45, 1.4);
    const canopyMat = new THREE.MeshStandardMaterial({
      color: 0x00d2ff,
      roughness: 0.1,
      metalness: 0.9,
    });
    const canopy = new THREE.Mesh(canopyGeo, canopyMat);
    canopy.position.set(0, 0.42, 0);
    canopy.castShadow = true;
    this.droneGroup.add(canopy);

    // Gimbal Camera on Nose (Facing forward -Z in Three.js)
    const cameraMount = new THREE.Mesh(
      new THREE.SphereGeometry(0.18, 16, 16),
      new THREE.MeshStandardMaterial({ color: 0x000000, metalness: 0.9 })
    );
    cameraMount.position.set(0, 0.15, -0.65);
    this.droneGroup.add(cameraMount);

    // 4 Quadcopter Arms extending at 45 degree diagonals
    const armGeo = new THREE.CylinderGeometry(0.045, 0.045, 1.3, 8);
    const armMat = new THREE.MeshStandardMaterial({ color: 0x334155, metalness: 0.7 });

    const armAngles = [Math.PI / 4, (3 * Math.PI) / 4, (5 * Math.PI) / 4, (7 * Math.PI) / 4];
    const armRadius = 0.85;

    this.rotors = [];

    armAngles.forEach((angle, idx) => {
      // Arm cylinder
      const arm = new THREE.Mesh(armGeo, armMat);
      arm.rotation.z = Math.PI / 2;
      arm.rotation.y = angle;
      arm.position.set(0, 0.25, 0);
      arm.castShadow = true;
      this.droneGroup.add(arm);

      // Motor Nacelle at arm tip
      const nx = Math.cos(angle) * armRadius;
      const nz = Math.sin(angle) * armRadius;

      const motorGeo = new THREE.CylinderGeometry(0.1, 0.1, 0.22, 12);
      const motorMat = new THREE.MeshStandardMaterial({ color: 0x1e293b, metalness: 0.9 });
      const motor = new THREE.Mesh(motorGeo, motorMat);
      motor.position.set(nx, 0.32, nz);
      motor.castShadow = true;
      this.droneGroup.add(motor);

      // Propeller Rotor Assembly
      const rotorGroup = new THREE.Group();
      rotorGroup.position.set(nx, 0.44, nz);

      // Rotor Blades (Two aerodynamic blades)
      const bladeGeo = new THREE.BoxGeometry(0.75, 0.015, 0.08);
      const bladeMat = new THREE.MeshStandardMaterial({
        color: idx < 2 ? 0xffffff : 0x00d2ff,
        transparent: true,
        opacity: 0.85,
      });
      const blade = new THREE.Mesh(bladeGeo, bladeMat);
      rotorGroup.add(blade);

      this.droneGroup.add(rotorGroup);
      this.rotors.push(rotorGroup);

      // Navigation Tip LEDs
      const ledColor = idx === 0 ? 0x00ff9d : idx === 1 ? 0xff3366 : 0xffffff;
      const ledGeo = new THREE.SphereGeometry(0.04, 8, 8);
      const ledMat = new THREE.MeshBasicMaterial({ color: ledColor });
      const led = new THREE.Mesh(ledGeo, ledMat);
      led.position.set(nx, 0.22, nz);
      this.droneGroup.add(led);
    });

    // Landing Skids (Legs)
    const legMat = new THREE.MeshStandardMaterial({ color: 0x1e293b });
    [-0.35, 0.35].forEach((lx) => {
      const legBar = new THREE.Mesh(new THREE.BoxGeometry(0.04, 0.04, 1.1), legMat);
      legBar.position.set(lx, 0.02, 0);
      legBar.castShadow = true;
      this.droneGroup.add(legBar);

      // Struts
      [-0.3, 0.3].forEach((lz) => {
        const strut = new THREE.Mesh(new THREE.CylinderGeometry(0.025, 0.025, 0.24, 6), legMat);
        strut.position.set(lx, 0.12, lz);
        this.droneGroup.add(strut);
      });
    });

    // Belly Status Beacon LED
    const bellyGeo = new THREE.SphereGeometry(0.08, 12, 12);
    this.bellyBeaconMat = new THREE.MeshStandardMaterial({
      color: 0xff3366,
      emissive: 0xff3366,
      emissiveIntensity: 1.0,
    });
    const bellyBeacon = new THREE.Mesh(bellyGeo, this.bellyBeaconMat);
    bellyBeacon.position.set(0, 0.08, 0);
    this.droneGroup.add(bellyBeacon);

    this.scene.add(this.droneGroup);

    // Ground Shadow Projection (Plane beneath drone that scales with altitude)
    const shadowGeo = new THREE.PlaneGeometry(1.4, 1.4);
    const shadowMat = new THREE.MeshBasicMaterial({
      color: 0x000000,
      transparent: true,
      opacity: 0.45,
      depthWrite: false,
    });
    this.droneShadow = new THREE.Mesh(shadowGeo, shadowMat);
    this.droneShadow.rotation.x = -Math.PI / 2;
    this.droneShadow.position.set(0, 0.04, 0);
    this.scene.add(this.droneShadow);
  }

  buildFlightTrail() {
    const maxPoints = this.maxTrailPoints;
    const positions = new Float32Array(maxPoints * 3);
    const trailGeo = new THREE.BufferGeometry();
    trailGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));

    const trailMat = new THREE.LineBasicMaterial({
      color: 0x00d2ff,
      transparent: true,
      opacity: 0.6,
      linewidth: 2,
    });

    this.flightTrail = new THREE.Line(trailGeo, trailMat);
    this.scene.add(this.flightTrail);
  }

  updateTrail(pos) {
    this.trailPoints.push(pos.clone());
    if (this.trailPoints.length > this.maxTrailPoints) {
      this.trailPoints.shift();
    }

    const posAttr = this.flightTrail.geometry.attributes.position;
    for (let i = 0; i < this.trailPoints.length; i++) {
      posAttr.setXYZ(i, this.trailPoints[i].x, this.trailPoints[i].y, this.trailPoints[i].z);
    }
    // Zero out unused points to avoid line artifacts
    for (let i = this.trailPoints.length; i < this.maxTrailPoints; i++) {
      posAttr.setXYZ(i, pos.x, pos.y, pos.z);
    }
    posAttr.needsUpdate = true;
    this.flightTrail.geometry.setDrawRange(0, this.trailPoints.length);
  }

  /**
   * Update authoritative state received from WebSocket telemetry.
   */
  updateTelemetry(data) {
    if (!data) return;

    this.targetState.x = typeof data.x === 'number' ? data.x : this.targetState.x;
    this.targetState.y = typeof data.y === 'number' ? data.y : this.targetState.y;
    this.targetState.z = typeof data.z === 'number' ? data.z : this.targetState.z;
    this.targetState.heading = typeof data.heading === 'number' ? data.heading : this.targetState.heading;
    this.targetState.speed = typeof data.speed === 'number' ? data.speed : this.targetState.speed;
    this.targetState.flightState = data.flight_state || this.targetState.flightState;
    this.targetState.armed = this.targetState.flightState !== 'DISARMED';

    // Update belly beacon color based on state
    if (this.bellyBeaconMat) {
      if (this.targetState.flightState === 'DISARMED') {
        this.bellyBeaconMat.color.setHex(0xff3366); // Red
        this.bellyBeaconMat.emissive.setHex(0xff3366);
      } else if (this.targetState.flightState === 'ARMED') {
        this.bellyBeaconMat.color.setHex(0xffb800); // Amber
        this.bellyBeaconMat.emissive.setHex(0xffb800);
      } else if (this.targetState.flightState === 'HOVERING') {
        this.bellyBeaconMat.color.setHex(0x00ff9d); // Emerald
        this.bellyBeaconMat.emissive.setHex(0x00ff9d);
      } else {
        this.bellyBeaconMat.color.setHex(0x00d2ff); // Cyan
        this.bellyBeaconMat.emissive.setHex(0x00d2ff);
      }
    }
  }

  setCameraMode(mode) {
    this.cameraMode = mode;
    if (mode === 'TOPDOWN') {
      this.camera.position.set(0, 110, 0);
      this.controls.target.set(0, 0, 0);
    } else if (mode === 'TOWER') {
      this.camera.position.copy(this.towerPosition);
      this.controls.target.set(this.droneGroup.position.x, this.droneGroup.position.y, this.droneGroup.position.z);
    } else if (mode === 'ORBIT') {
      this.controls.target.set(0, 2, 0);
    }
  }

  resetCamera() {
    this.cameraMode = 'ORBIT';
    this.camera.position.set(18, 14, 24);
    this.controls.target.set(0, 2, 0);
  }

  animate() {
    this.animId = requestAnimationFrame(() => this.animate());

    const delta = this.clock.getDelta();
    const elapsedTime = this.clock.getElapsedTime();

    // 1. Map backend local coordinates (x, y, z) to Three.js world coordinates:
    //    ThreeX = +X, ThreeY = +Y, ThreeZ = -Z
    const targetThreeX = this.targetState.x;
    const targetThreeY = this.targetState.y;
    const targetThreeZ = -this.targetState.z;
    const targetThreeRotY = -(this.targetState.heading * Math.PI / 180);

    // Smooth lerp interpolation for silky 60fps rendering without lag
    if (this.droneGroup) {
      this.droneGroup.position.x += (targetThreeX - this.droneGroup.position.x) * 0.25;
      this.droneGroup.position.y += (targetThreeY - this.droneGroup.position.y) * 0.25;
      this.droneGroup.position.z += (targetThreeZ - this.droneGroup.position.z) * 0.25;

      // Handle yaw angular interpolation smoothly
      this.droneGroup.rotation.y += (targetThreeRotY - this.droneGroup.rotation.y) * 0.25;

      // Update flight trail
      this.updateTrail(this.droneGroup.position);

      // Update ground shadow projection
      if (this.droneShadow) {
        this.droneShadow.position.x = this.droneGroup.position.x;
        this.droneShadow.position.z = this.droneGroup.position.z;
        // Shadow fades and scales larger with altitude
        const altRatio = Math.max(0, this.droneGroup.position.y / 50.0);
        const scale = 1.0 + altRatio * 2.5;
        this.droneShadow.scale.set(scale, scale, 1);
        this.droneShadow.material.opacity = Math.max(0.08, 0.45 - altRatio * 0.4);
      }

      // Propeller spin animation based on flight state
      const isSpinning = this.targetState.flightState !== 'DISARMED';
      const spinSpeed = isSpinning ? (this.targetState.flightState === 'ARMED' ? 15 : 45) : 0;

      this.rotors.forEach((rotor, idx) => {
        const dir = idx % 2 === 0 ? 1 : -1;
        rotor.rotation.y += spinSpeed * delta * dir;
      });
    }

    // 2. Tower Warning Beacon Flash
    if (this.towerBeacon) {
      const flash = Math.sin(elapsedTime * 4.0) > 0.3 ? 1.5 : 0.1;
      this.towerBeacon.material.emissiveIntensity = flash;
    }

    // 3. Radar Dish Rotation
    if (this.radarDish) {
      this.radarDish.rotation.z += delta * 0.8;
    }

    // 4. Camera Chase Mode Logic
    if (this.cameraMode === 'CHASE' && this.droneGroup) {
      const offset = new THREE.Vector3(0, 3.5, 7.5);
      offset.applyAxisAngle(new THREE.Vector3(0, 1, 0), this.droneGroup.rotation.y);
      const desiredPos = this.droneGroup.position.clone().add(offset);
      this.camera.position.lerp(desiredPos, 0.1);
      this.controls.target.lerp(this.droneGroup.position, 0.1);
    } else if (this.cameraMode === 'TOWER' && this.droneGroup) {
      this.controls.target.lerp(this.droneGroup.position, 0.1);
    }

    this.controls.update();
    this.renderer.render(this.scene, this.camera);
  }

  onWindowResize() {
    if (!this.canvas || !this.renderer || !this.camera) return;
    const width = this.canvas.clientWidth;
    const height = this.canvas.clientHeight;
    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height);
  }

  destroy() {
    if (this.animId) {
      cancelAnimationFrame(this.animId);
    }
    window.removeEventListener('resize', this.onWindowResize);
    if (this.renderer) {
      this.renderer.dispose();
    }
  }
}
