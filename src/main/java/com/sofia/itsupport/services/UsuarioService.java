package com.sofia.itsupport.services;

import com.sofia.itsupport.dto.request.CrearUsuarioRequest;
import com.sofia.itsupport.dto.response.UsuarioResponseDTO;
import com.sofia.itsupport.entities.Area;
import com.sofia.itsupport.entities.Usuario;
import com.sofia.itsupport.enums.EstadoCuenta;
import com.sofia.itsupport.enums.RolUsuario;
import com.sofia.itsupport.repositories.AreaRepository;
import com.sofia.itsupport.repositories.TicketRepository;
import com.sofia.itsupport.repositories.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UsuarioService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private AreaRepository areaRepository;

    @Autowired
    private TicketRepository ticketRepository;

    // ===========================================
    // REGISTRAR USUARIO
    // ===========================================
    @Transactional
    public UsuarioResponseDTO registrarUsuario(CrearUsuarioRequest request) {
        // Validar email único
        if (usuarioRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("El email ya está registrado");
        }

        // Validar nombre de usuario único
        if (usuarioRepository.existsByNombreUsuario(request.getNombreUsuario())) {
            throw new RuntimeException("El nombre de usuario ya existe");
        }

        // Validar área si es encargado
        Area area = null;
        if (request.getRol() == RolUsuario.encargado) {
            if (request.getAreaId() == null) {
                throw new RuntimeException("Un encargado debe tener un área asignada");
            }
            area = areaRepository.findById(request.getAreaId())
                    .orElseThrow(() -> new RuntimeException("Área no encontrada"));
        }

        // Crear usuario con contraseña hasheada
        Usuario usuario = new Usuario();
        usuario.setNombreUsuario(request.getNombreUsuario());
        usuario.setEmail(request.getEmail());
        usuario.setContrasenaHash(passwordEncoder.encode(request.getContrasena())); // ← HASHEADA
        usuario.setRol(request.getRol());
        usuario.setEstadoCuenta(EstadoCuenta.activo);
        usuario.setArea(area);

        usuario = usuarioRepository.save(usuario);

        return convertirADTO(usuario);
    }

    // ===========================================
    // OBTENER USUARIO POR ID
    // ===========================================
    @Transactional(readOnly = true)
    public UsuarioResponseDTO obtenerUsuarioPorId(Long id) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
        return convertirADTO(usuario);
    }

    // ===========================================
    // LISTAR TODOS LOS USUARIOS
    // ===========================================
    @Transactional(readOnly = true)
    public List<UsuarioResponseDTO> listarTodos() {
        return usuarioRepository.findAll().stream()
                .map(this::convertirADTO)
                .collect(Collectors.toList());
    }

    // ===========================================
    // LISTAR TÉCNICOS ACTIVOS
    // ===========================================
    @Transactional(readOnly = true)
    public List<UsuarioResponseDTO> listarTecnicosActivos() {
        return usuarioRepository.findByRolAndEstadoCuenta(RolUsuario.tecnico, EstadoCuenta.activo)
                .stream()
                .map(this::convertirADTO)
                .collect(Collectors.toList());
    }

    // ===========================================
    // SUSPENDER USUARIO
    // ===========================================
    @Transactional
    public UsuarioResponseDTO suspenderUsuario(Long id) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        usuario.setEstadoCuenta(EstadoCuenta.suspendido);
        usuario = usuarioRepository.save(usuario);

        return convertirADTO(usuario);
    }

    // ===========================================
    // ACTIVAR USUARIO
    // ===========================================
    @Transactional
    public UsuarioResponseDTO activarUsuario(Long id) {
        Usuario usuario = usuarioRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        usuario.setEstadoCuenta(EstadoCuenta.activo);
        usuario = usuarioRepository.save(usuario);

        return convertirADTO(usuario);
    }

    // ===========================================
    // MÉTODO PRIVADO: Convertir Entity → DTO
    // ===========================================
    private UsuarioResponseDTO convertirADTO(Usuario usuario) {
        UsuarioResponseDTO dto = new UsuarioResponseDTO();

        dto.setId(usuario.getId());
        dto.setNombreUsuario(usuario.getNombreUsuario());
        dto.setEmail(usuario.getEmail());
        dto.setRol(usuario.getRol());
        dto.setEstadoCuenta(usuario.getEstadoCuenta());

        if (usuario.getArea() != null) {
            dto.setAreaNombre(usuario.getArea().getNombre());
            dto.setAreaId(usuario.getArea().getId());
        }

        // Contar tickets según el rol
        if (usuario.getRol() == RolUsuario.tecnico) {
            // Tickets activos (en proceso)
            long activos = usuario.getTicketsAsignados().stream()
                    .filter(t -> t.getEstado().name().equals("en_proceso"))
                    .count();
            dto.setTicketsActivos((int) activos);

            // Tickets resueltos
            long resueltos = usuario.getTicketsAsignados().stream()
                    .filter(t -> t.getEstado().name().equals("cerrado"))
                    .count();
            dto.setTicketsResueltos((int) resueltos);

        } else if (usuario.getRol() == RolUsuario.encargado) {
            dto.setTicketsCreados(usuario.getTicketsCreados().size());
        }

        return dto;
    }
}
