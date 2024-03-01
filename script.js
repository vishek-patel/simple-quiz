import { questionsArr } from "./constants.js";

        const questions = questionsArr
        const quizContainer = document.getElementById('quiz');
        const submitBtn = document.getElementById('submitBtn');

        function generateQuiz() {
            let quizHTML = '';
            questions.forEach(question => {
                quizHTML += `
                    <div class="question">
                        <h3>Question ${question['Question No']}:</h3>
                        <p>${question['Question']}</p>
                        <div class="options">
                `;
                for (let i = 1; i <= 4; i++) {
                    if (question[`Option ${i}`]) {
                        quizHTML += `
                            <div class="option">
                                <input type="radio" name="question${question['Question No']}" value="${question[`Option ${i}`]}">
                                <label>${question[`Option ${i}`]}</label>
                            </div>
                        `;
                    }
                }
                quizHTML += `</div></div>`;
            });
            quizContainer.innerHTML = quizHTML;
        }

        generateQuiz();

        submitBtn.addEventListener('click', () => {
            let totalMarks = 0;
            let incorrectAnswers = [];

            questions.forEach(question => {
                const selectedOption = document.querySelector(`input[name="question${question['Question No']}"]:checked`);
                if (selectedOption) {
                    if (selectedOption.value === question['Correct answer']) {
                        totalMarks++;
                    } else {
                        incorrectAnswers.push({
                            questionNumber: question['Question No'],
                            correctAnswer: question['Correct answer']
                        });
                    }
                }
            });

            // Display total marks and incorrect answers
            let resultHTML = `<h2>Result</h2>`;
            resultHTML += `<p>Total Marks: ${totalMarks}/${questions.length}</p>`;
            if (incorrectAnswers.length > 0) {
                resultHTML += `<p>Incorrect Answers:</p>`;
                incorrectAnswers.forEach(answer => {
                    resultHTML += `<p>Question ${answer.questionNumber}: Correct answer is ${answer.correctAnswer}</p>`;
                });
            } else {
                resultHTML += `<p>Congratulations! You answered all questions correctly.</p>`;
            }

            // Append result to the quiz container
            quizContainer.innerHTML += resultHTML;
        });
