package dev.vetto.jetbrains

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.process.CapturingProcessHandler
import com.intellij.execution.process.ProcessOutput
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import com.intellij.util.execution.ParametersListUtil
import java.awt.BorderLayout
import java.awt.Desktop
import java.awt.FlowLayout
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Comparator
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextArea
import javax.swing.JTextField

class VettoToolWindowFactory : ToolWindowFactory {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val root = project.basePath ?: System.getProperty("user.dir")
        val stateDir = Paths.get(System.getProperty("user.home"), ".vetto", "jetbrains")
        Files.createDirectories(stateDir)

        val command = JTextField("codex exec \"review this project\"", 48)
        val executable = JTextField("vetto", 10)
        val profile = JComboBox(arrayOf("default", "strict", "audit", "permissive"))
        val network = JTextField("off", 24)
        val output = JTextArea().apply {
            isEditable = false
            lineWrap = false
        }
        val run = JButton("Run headless")
        val doctor = JButton("Doctor")
        val report = JButton("Open last report")

        fun execute(extra: List<String>) {
            run.isEnabled = false
            doctor.isEnabled = false
            output.text = "Starting vetto…\n"
            ApplicationManager.getApplication().executeOnPooledThread {
                val result = runCommand(executable.text.trim(), root, extra)
                ApplicationManager.getApplication().invokeLater {
                    output.text = render(result)
                    run.isEnabled = true
                    doctor.isEnabled = true
                }
            }
        }

        run.addActionListener {
            val agent = ParametersListUtil.parse(command.text)
            if (agent.isEmpty()) {
                Messages.showErrorDialog(project, "Enter an agent command.", "vetto")
                return@addActionListener
            }
            execute(
                listOf(
                    "--profile", profile.selectedItem.toString(),
                    "--net", network.text.trim(),
                    "--tui", "none",
                    "--jsonl", stateDir.resolve("session.jsonl").toString(),
                    "--report", "html,json",
                    "--report-dir", stateDir.resolve("reports").toString(),
                    "--",
                ) + agent,
            )
        }
        doctor.addActionListener { execute(listOf("doctor")) }
        report.addActionListener {
            val last = newestHtmlReport(stateDir.resolve("reports"))
            if (last == null) {
                Messages.showInfoMessage(project, "No HTML report has been generated yet.", "vetto")
            } else if (!Desktop.isDesktopSupported()) {
                Messages.showInfoMessage(project, last.toString(), "Latest vetto report")
            } else {
                Desktop.getDesktop().browse(last.toUri())
            }
        }

        val controls = JPanel(FlowLayout(FlowLayout.LEFT)).apply {
            add(JLabel("Binary"))
            add(executable)
            add(JLabel("Profile"))
            add(profile)
            add(JLabel("Network"))
            add(network)
            add(doctor)
            add(report)
        }
        val commandRow = JPanel(BorderLayout(8, 0)).apply {
            add(command, BorderLayout.CENTER)
            add(run, BorderLayout.EAST)
        }
        val top = JPanel(BorderLayout(0, 8)).apply {
            add(controls, BorderLayout.NORTH)
            add(commandRow, BorderLayout.CENTER)
        }
        val panel = JPanel(BorderLayout(0, 8)).apply {
            add(top, BorderLayout.NORTH)
            add(JBScrollPane(output), BorderLayout.CENTER)
        }
        val content = ContentFactory.getInstance().createContent(panel, "Session", false)
        toolWindow.contentManager.addContent(content)
    }

    private fun runCommand(executable: String, cwd: String, args: List<String>): ProcessOutput {
        val commandLine = GeneralCommandLine(executable)
            .withWorkDirectory(cwd)
            .withParameters(args)
            .withCharset(Charsets.UTF_8)
        return CapturingProcessHandler(commandLine).runProcess(4 * 60 * 60 * 1000)
    }

    private fun render(result: ProcessOutput): String = buildString {
        append(result.stdout)
        if (result.stderr.isNotBlank()) {
            if (isNotEmpty() && !endsWith("\n")) append('\n')
            append(result.stderr)
        }
        if (isNotEmpty() && !endsWith("\n")) append('\n')
        append("exit=").append(result.exitCode).append('\n')
    }

    private fun newestHtmlReport(directory: Path): Path? {
        if (!Files.isDirectory(directory)) return null
        return Files.list(directory).use { paths ->
            paths
                .filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".html") }
                .max(Comparator.comparingLong { Files.getLastModifiedTime(it).toMillis() })
                .orElse(null)
        }
    }
}
